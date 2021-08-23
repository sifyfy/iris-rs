pub mod writer {
    use crossbeam::channel::{Receiver, Sender};
    use std::io::Write;
    use tracing_subscriber::fmt::MakeWriter;

    pub struct MakeTestWriter {
        tx: Sender<String>,
    }

    impl MakeTestWriter {
        pub fn new() -> (Self, Receiver<String>) {
            let (tx, rx) = crossbeam::channel::unbounded();
            (MakeTestWriter { tx }, rx)
        }
    }

    impl MakeWriter for MakeTestWriter {
        type Writer = TestWriter;

        fn make_writer(&self) -> Self::Writer {
            TestWriter::new(self.tx.clone())
        }
    }

    pub struct TestWriter {
        buf: Vec<u8>,
        tx: Sender<String>,
    }

    impl TestWriter {
        pub fn new(tx: Sender<String>) -> Self {
            TestWriter {
                buf: Vec::with_capacity(1024),
                tx,
            }
        }
    }

    impl Write for TestWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.buf.write(buf)?;

            let mut pos_l = 0;
            let mut pos_r = 0;
            let mut skip = false;
            for i in 0..self.buf.len() {
                if skip {
                    skip = false;
                    continue;
                }

                let mut next_pos_l = pos_l;
                match self.buf[i] {
                    b'\n' => {
                        pos_r = i;
                        next_pos_l = pos_r + 1;
                    }
                    b'\r' => {
                        pos_r = i;
                        skip = i + 1 < self.buf.len() && self.buf[i + 1] == b'\n';
                        next_pos_l = pos_r + if skip { 2 } else { 1 };
                    }
                    _ => (),
                };

                if pos_l != pos_r {
                    let log = String::from_utf8_lossy(&self.buf[pos_l..pos_r]).to_string();
                    self.tx.send(log).unwrap();
                    pos_l = next_pos_l;
                } else if self.buf[i] == b'\n' || self.buf[i] == b'\r' {
                    self.tx.send(String::new()).unwrap();
                    pos_l = next_pos_l;
                }
            }

            if pos_l < self.buf.len() {
                self.buf = self.buf.split_off(pos_l);
            } else {
                self.buf.clear();
            }

            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.buf.flush()
        }
    }
}

use crossbeam::channel::Receiver;
use regex::Regex;
use tracing::subscriber::DefaultGuard;
use tracing_subscriber::fmt::{format::DefaultFields, FormatEvent};
use tracing_subscriber::Registry;

fn set_local_subscriber<E>(
    fmt_event: E,
    max_level: tracing::Level,
) -> (DefaultGuard, Receiver<String>)
where
    E: FormatEvent<Registry, DefaultFields> + Send + Sync + 'static,
{
    let (mk_writer, rx) = writer::MakeTestWriter::new();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(max_level)
        .event_format(fmt_event)
        .with_writer(mk_writer)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);

    (guard, rx)
}

fn app_log_regex(level: &str, message: &str) -> Result<Regex, regex::Error> {
    Regex::new(&format!(
        r#"^\[\d{{4}}-\d{{2}}-\d{{2}}T\d{{2}}:\d{{2}}:\d{{2}}.\d+[+-]\d{{2}}:\d{{2}}]\[{level}] {message}$"#,
        level = level,
        message = message
    ))
}

fn app_log_debug_regex(
    level: &str,
    span: &str,
    message: &str,
    file: &str,
    line: u32,
) -> Result<Regex, regex::Error> {
    Regex::new(&format!(
        r#"^\[\d{{4}}-\d{{2}}-\d{{2}}T\d{{2}}:\d{{2}}:\d{{2}}.\d+[+-]\d{{2}}:\d{{2}}]\[{level}]\[{span}] {message} at {file}:{line}$"#,
        level = level,
        span = span,
        message = message,
        file = file,
        line = line,
    ))
}

fn server_log_regex(
    level: &str,
    span: Option<&str>,
    target: &str,
    message: &str,
    fields: Option<&str>,
    file: Option<&str>,
    line: Option<u32>,
) -> Result<Regex, regex::Error> {
    Regex::new(&format!(
        r#"^\{{"timestamp":"\d{{4}}-\d{{2}}-\d{{2}}T\d{{2}}:\d{{2}}:\d{{2}}.\d+[+-]\d{{2}}:\d{{2}}","level":"{level}","target":"{target}","span":{span},"message":"{message}"{fields},"file":{file},"line":{line}}}$"#,
        level = level,
        target = target,
        span = span
            .map(|span| format!("\"{}\"", span))
            .unwrap_or_else(|| "null".to_string()),
        message = message,
        fields = fields
            .map(|fields| format!(",{}", fields))
            .unwrap_or_else(|| "".to_string()),
        file = file
            .map(|file| format!("\"{}\"", file))
            .unwrap_or_else(|| "null".to_string()),
        line = line
            .map(|line| line.to_string())
            .unwrap_or_else(|| "null".to_string()),
    ))
}

macro_rules! assert_regex {
    ($re:expr, $value:expr) => {
        assert!(
            $re.is_match($value),
            "Expected pattern: {}\n    Actual value: {}",
            $re,
            $value
        )
    };
}

#[test]
fn basic_logging_1() {
    let fmt_event = iris::log::FormatForApp::simple();
    let (_guard, rx) = set_local_subscriber(fmt_event, tracing::Level::TRACE);

    {
        iris::log::trace!("TRACE!");
        let msg = format!("{}", rx.try_recv().unwrap().escape_default());
        let re = app_log_regex("TRACE", "TRACE!").unwrap();
        assert_regex!(re, msg.as_str());
    }
}

#[test]
fn basic_logging_2() {
    let fmt_event = iris::log::FormatForApp::simple_utc();
    let (_guard, rx) = set_local_subscriber(fmt_event, tracing::Level::TRACE);

    {
        iris::log::debug!("DEBUG!");
        let msg = format!("{}", rx.try_recv().unwrap().escape_default());
        let re = app_log_regex("DEBUG", "DEBUG!").unwrap();
        assert_regex!(re, msg.as_str());
    }
}

#[test]
fn basic_logging_3() {
    let fmt_event = iris::log::FormatForApp::debug();
    let (_guard, rx) = set_local_subscriber(fmt_event, tracing::Level::TRACE);

    {
        iris::log::info!("INFO!");
        let msg = format!("{}", rx.try_recv().unwrap().escape_default());
        let re = app_log_debug_regex("INFO", "", "INFO!", "tests/logging.rs", line!() - 2).unwrap();
        assert_regex!(re, msg.as_str());
    }

    {
        {
            let span = iris::log::tracing::span!(iris::log::Level::INFO, "span1");
            let _guard = span.enter();
            {
                let span = iris::log::tracing::span!(iris::log::Level::INFO, "span2");
                let _guard = span.enter();

                iris::log::info!("INFO!");
            }
        }
        let msg = format!("{}", rx.try_recv().unwrap().escape_default());
        let re = app_log_debug_regex(
            "INFO",
            "span1 -> span2",
            "INFO!",
            "tests/logging\\.rs",
            line!() - 9,
        )
        .unwrap();
        assert_regex!(re, msg.as_str());
    }

    {
        {
            let span = iris::log::tracing::span!(iris::log::Level::INFO, "span1");
            let _guard = span.enter();
            {
                let span = iris::log::tracing::span!(iris::log::Level::INFO, "span2");
                let _guard = span.enter();

                iris::log::info!("INFO (enter span1, then enter span2)");
            }
            {
                let span = iris::log::tracing::span!(iris::log::Level::INFO, "span2");
                let _guard = span.enter();

                iris::log::info!(
                    "INFO {{ enter span1, then enter span2, then return span1, then enter span3 }}"
                );
            }
        }
        let msg = format!("{}", rx.try_recv().unwrap().escape_default());
        let re = app_log_debug_regex(
            "INFO",
            "span1 -> span2",
            "INFO \\(enter span1, then enter span2\\)",
            "tests/logging\\.rs",
            line!() - 17,
        )
        .unwrap();
        assert_regex!(re, msg.as_str());

        let msg = format!("{}", rx.try_recv().unwrap().escape_default());
        let re = app_log_debug_regex(
            "INFO",
            "span1 -> span2",
            "INFO \\{ enter span1, then enter span2, then return span1, then enter span3 }",
            "tests/logging\\.rs",
            line!() - 22,
        )
        .unwrap();
        assert_regex!(re, msg.as_str());
    }
}

#[test]
fn basic_logging_4() {
    let fmt_event = iris::log::FormatForApp::debug_utc();
    let (_guard, rx) = set_local_subscriber(fmt_event, tracing::Level::TRACE);

    {
        iris::log::warn!("WARN!");
        let msg = format!("{}", rx.try_recv().unwrap().escape_default());
        let re = app_log_debug_regex("WARN", "", "WARN!", "tests/logging.rs", line!() - 2).unwrap();
        assert_regex!(re, msg.as_str());
    }

    {
        {
            let span = iris::log::tracing::span!(iris::log::Level::WARN, "span1");
            let _guard = span.enter();
            {
                let span = iris::log::tracing::span!(iris::log::Level::WARN, "span2");
                let _guard = span.enter();

                iris::log::warn!("WARN!");
            }
        }
        let msg = format!("{}", rx.try_recv().unwrap().escape_default());
        let re = app_log_debug_regex(
            "WARN",
            "span1 -> span2",
            "WARN!",
            "tests/logging\\.rs",
            line!() - 9,
        )
        .unwrap();
        assert_regex!(re, msg.as_str());
    }

    {
        {
            let span = iris::log::tracing::span!(iris::log::Level::WARN, "span1");
            let _guard = span.enter();
            {
                let span = iris::log::tracing::span!(iris::log::Level::WARN, "span2");
                let _guard = span.enter();

                iris::log::warn!("WARN (enter span1, then enter span2)");
            }
            {
                let span = iris::log::tracing::span!(iris::log::Level::WARN, "span2");
                let _guard = span.enter();

                iris::log::warn!(
                    "WARN {{ enter span1, then enter span2, then return span1, then enter span3 }}"
                );
            }
        }
        let msg = format!("{}", rx.try_recv().unwrap().escape_default());
        let re = app_log_debug_regex(
            "WARN",
            "span1 -> span2",
            "WARN \\(enter span1, then enter span2\\)",
            "tests/logging\\.rs",
            line!() - 17,
        )
        .unwrap();
        assert_regex!(re, msg.as_str());

        let msg = format!("{}", rx.try_recv().unwrap().escape_default());
        let re = app_log_debug_regex(
            "WARN",
            "span1 -> span2",
            "WARN \\{ enter span1, then enter span2, then return span1, then enter span3 }",
            "tests/logging\\.rs",
            line!() - 22,
        )
        .unwrap();
        assert_regex!(re, msg.as_str());
    }
}

#[test]
fn basic_logging_5() {
    let fmt_event = iris::log::FormatForServer::local();
    let (_guard, rx) = set_local_subscriber(fmt_event, tracing::Level::TRACE);

    {
        iris::log::error!("ERROR!");
        let msg = rx.try_recv().unwrap();
        let re = server_log_regex(
            "ERROR",
            None,
            "logging",
            "ERROR!",
            None,
            Some("tests/logging\\.rs"),
            Some(line!() - 9),
        )
        .unwrap();
        assert_regex!(re, msg.as_str());
    }
}
