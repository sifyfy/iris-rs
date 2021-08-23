//! # iris::log
//!
//! ## Usage
//!
//! In app:
//! ```
//! iris::log::Tracer::builder()
//!     .format_for_app_simple()
//!     .init()
//!     .unwrap();
//!
//! iris::log::error!("Error");
//! ```
//!
//! In server:
//! ```
//! iris::log::Tracer::builder()
//!     .format_for_server()
//!     .init()
//!     .unwrap();
//!
//! iris::log::error!("");
//! ```
//!

mod format_time {
    use tracing_subscriber::fmt::time::{ChronoLocal, ChronoUtc};

    pub type Local = ChronoLocal;
    pub type Utc = ChronoUtc;
}

mod format_fields {}

mod format_event {
    use super::format_time::{Local, Utc};
    use serde::ser::{SerializeMap, Serializer};
    use std::fmt::Write;
    use std::marker::PhantomData;
    use thiserror::private::DisplayAsDisplay;
    use tracing::{Event, Subscriber};
    use tracing_log::NormalizeEvent;
    use tracing_subscriber::fmt::time::FormatTime;
    use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, FormattedFields};
    use tracing_subscriber::registry::{LookupSpan, SpanRef};

    #[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Default)]
    pub struct Simple;

    #[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Default)]
    pub struct Debug;

    #[derive(Debug, Clone)]
    pub struct FormatForApp<M, T> {
        log_mode: M,
        format_time: T,
    }

    impl<M: Default, T: FormatTime> FormatForApp<M, T> {
        pub fn new(format_time: T) -> Self {
            FormatForApp {
                log_mode: M::default(),
                format_time,
            }
        }
    }

    impl FormatForApp<Simple, Local> {
        pub fn simple() -> Self {
            Default::default()
        }
    }

    impl FormatForApp<Simple, Utc> {
        pub fn simple_utc() -> Self {
            Default::default()
        }
    }

    impl FormatForApp<Debug, Local> {
        pub fn debug() -> Self {
            Default::default()
        }
    }

    impl FormatForApp<Debug, Utc> {
        pub fn debug_utc() -> Self {
            Default::default()
        }
    }

    impl<M, T> Default for FormatForApp<M, T>
    where
        M: Default,
        T: Default + FormatTime,
    {
        fn default() -> Self {
            Self::new(T::default())
        }
    }

    impl<S, N, T> FormatEvent<S, N> for FormatForApp<Simple, T>
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
        N: for<'a> FormatFields<'a> + 'static,
        T: FormatTime,
    {
        fn format_event(
            &self,
            ctx: &FmtContext<'_, S, N>,
            writer: &mut dyn Write,
            event: &Event<'_>,
        ) -> std::fmt::Result {
            {
                write!(writer, "[")?;
                self.format_time.format_time(writer)?;
                write!(writer, "]")?;
            }
            {
                let normalized_metadata = event.normalized_metadata();
                let metadata = normalized_metadata
                    .as_ref()
                    .unwrap_or_else(|| event.metadata());
                write!(writer, "[{level}]", level = metadata.level().as_display())?;
            }
            {
                write!(writer, " ")?;
            }
            {
                ctx.format_fields(writer, event)?;
            }
            writeln!(writer)
        }
    }

    impl<S, N, T> FormatEvent<S, N> for FormatForApp<Debug, T>
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
        N: for<'a> FormatFields<'a> + 'static,
        T: FormatTime,
    {
        fn format_event(
            &self,
            ctx: &FmtContext<'_, S, N>,
            writer: &mut dyn Write,
            event: &Event<'_>,
        ) -> std::fmt::Result {
            let normalized_metadata = event.normalized_metadata();
            let metadata = normalized_metadata
                .as_ref()
                .unwrap_or_else(|| event.metadata());

            {
                write!(writer, "[")?;
                self.format_time.format_time(writer)?;
                write!(writer, "]")?;
            }
            {
                write!(writer, "[{level}]", level = metadata.level().as_display())?;
            }
            {
                write!(writer, "[")?;
                let mut is_first = true;
                ctx.visit_spans(|span| {
                    if is_first {
                        is_first = false;
                    } else {
                        write!(writer, " -> ")?;
                    }
                    write!(writer, "{}", span.name())?;
                    WriteSpan::<N, S>::write(writer, span)?;
                    Ok(())
                })?;
                write!(writer, "]")?;
            }
            {
                write!(writer, " ")?;
            }
            {
                ctx.format_fields(writer, event)?;
            }
            {
                let file = metadata.file().unwrap_or("unknown");
                let line = metadata.line().unwrap_or(0);
                write!(writer, " at {file}:{line}", file = file, line = line)?;
            }
            writeln!(writer)
        }
    }

    #[derive(Debug, Clone)]
    pub struct FormatForServer<T> {
        format_time: T,
    }

    impl<T: FormatTime + Default> FormatForServer<T> {
        pub fn new(format_time: T) -> Self {
            FormatForServer { format_time }
        }
    }

    impl FormatForServer<Local> {
        pub fn local() -> Self {
            Default::default()
        }
    }

    impl FormatForServer<Utc> {
        pub fn utc() -> Self {
            Default::default()
        }
    }

    impl<T: FormatTime + Default> Default for FormatForServer<T> {
        fn default() -> Self {
            FormatForServer::new(T::default())
        }
    }

    impl<S, N, T> FormatEvent<S, N> for FormatForServer<T>
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
        N: for<'a> FormatFields<'a> + 'static,
        T: FormatTime,
    {
        fn format_event(
            &self,
            ctx: &FmtContext<'_, S, N>,
            writer: &mut dyn Write,
            event: &Event<'_>,
        ) -> std::fmt::Result {
            (|| -> Result<(), JsonLogError> {
                let mut serializer = serde_json::Serializer::new(WriteAdapter::new(writer));
                let mut serializer = serializer.serialize_map(None)?;

                let normalized_metadata = event.normalized_metadata();
                let metadata = normalized_metadata
                    .as_ref()
                    .unwrap_or_else(|| event.metadata());

                let mut timestamp_buf = String::new();
                self.format_time.format_time(&mut timestamp_buf)?;
                serializer.serialize_entry("timestamp", timestamp_buf.as_str())?;

                serializer.serialize_entry("level", metadata.level().as_str())?;
                serializer.serialize_entry("target", metadata.target())?;

                let mut span_buf = String::new();
                let mut is_first = true;
                ctx.visit_spans(|span| -> std::fmt::Result {
                    if is_first {
                        is_first = false;
                    } else {
                        write!(&mut span_buf, " -> ")?;
                    }
                    write!(&mut span_buf, "{}", span.name())?;
                    WriteSpan::<N, S>::write(&mut span_buf, span)?;
                    Ok(())
                })?;
                serializer.serialize_entry(
                    "span",
                    &if !span_buf.is_empty() {
                        Some(span_buf.as_str())
                    } else {
                        None
                    },
                )?;

                let mut visitor = tracing_serde::SerdeMapVisitor::new(serializer);
                event.record(&mut visitor);
                serializer = visitor.take_serializer()?;

                serializer.serialize_entry("file", &metadata.file())?;
                serializer.serialize_entry("line", &metadata.line())?;

                serializer.end()?;

                Ok(())
            })()
            .map_err(|_| std::fmt::Error)?;

            writeln!(writer)
        }
    }

    #[derive(Debug, thiserror::Error)]
    enum JsonLogError {
        #[error("FmtError: {0}")]
        FmtError(#[from] std::fmt::Error),
        #[error("SerdeJsonError: {0}")]
        SerdeJsonError(#[from] serde_json::Error),
    }

    #[derive(Debug)]
    struct WriteSpan<N, S> {
        format_fields: PhantomData<N>,
        subscriber: PhantomData<S>,
    }

    impl<N, S> WriteSpan<N, S> {
        fn write(writer: &mut dyn Write, span: &SpanRef<S>) -> std::fmt::Result
        where
            N: 'static,
            S: Subscriber + for<'a> LookupSpan<'a>,
        {
            if let Some(fields) = span.extensions().get::<FormattedFields<N>>() {
                if !fields.is_empty() {
                    write!(writer, "{{{}}}", fields)?;
                }
            }
            Ok(())
        }
    }

    struct WriteAdapter<'a> {
        fmt_writer: &'a mut dyn Write,
    }

    impl<'a> WriteAdapter<'a> {
        fn new(fmt_writer: &'a mut dyn Write) -> Self {
            WriteAdapter { fmt_writer }
        }
    }

    impl<'a> std::io::Write for WriteAdapter<'a> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let s = String::from_utf8_lossy(buf);
            self.fmt_writer
                .write_str(&s)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}

pub use self::format_event::{Debug, FormatForApp, FormatForServer, Simple};
pub use self::format_time::{Local, Utc};
pub use tracing::{self, debug, error, info, level_filters::LevelFilter, trace, warn, Level};
pub use tracing_subscriber;

use crate::log::tracing_subscriber::fmt::MakeWriter;
use tracing::subscriber::SetGlobalDefaultError;
use tracing_log::{AsLog, LogTracer};
use tracing_subscriber::{fmt::format::DefaultFields, fmt::FormatEvent, Registry};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Default)]
pub struct Tracer;

impl Tracer {
    pub fn builder() -> Builder {
        Builder::default()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TracingInitError {
    #[error("TracingLogError: {0}")]
    TracingLogError(#[from] log::SetLoggerError),
    #[error("TracingError: {0}")]
    TracingError(#[from] SetGlobalDefaultError),
}

enum FormatEventKind {
    AppSimple,
    AppDebug,
    Server,
}

enum TimeLocale {
    Utc,
    Local,
}

pub struct Builder<W = fn() -> std::io::Stderr> {
    format_event_kind: FormatEventKind,
    time_locale: TimeLocale,
    max_level: LevelFilter,
    make_writer: W,
}

impl Default for Builder {
    fn default() -> Self {
        Builder {
            format_event_kind: FormatEventKind::AppSimple,
            time_locale: TimeLocale::Local,
            max_level: LevelFilter::ERROR,
            make_writer: std::io::stderr,
        }
    }
}

impl<W> Builder<W>
where W: MakeWriter + Send + Sync + 'static,
{
    pub fn new(make_writer: W) -> Self {
        let default = Builder::default();
        Builder {
            format_event_kind: default.format_event_kind,
            time_locale: default.time_locale,
            max_level: default.max_level,
            make_writer,
        }
    }

    pub fn format_for_app_simple(mut self) -> Self {
        self.format_event_kind = FormatEventKind::AppSimple;
        self
    }

    pub fn format_for_app_debug(mut self) -> Self {
        self.format_event_kind = FormatEventKind::AppDebug;
        self
    }

    pub fn format_for_server(mut self) -> Self {
        self.format_event_kind = FormatEventKind::Server;
        self
    }

    pub fn local_timestamp(mut self) -> Self {
        self.time_locale = TimeLocale::Local;
        self
    }

    pub fn utc_timestamp(mut self) -> Self {
        self.time_locale = TimeLocale::Utc;
        self
    }

    pub fn max_level(mut self, max_level: impl Into<LevelFilter>) -> Self {
        self.max_level = max_level.into();
        self
    }

    pub fn make_writer<W2: MakeWriter>(self, make_writer: W2) -> Builder<W2> {
        let Builder {
            format_event_kind,
            time_locale,
            max_level,
            ..
        } = self;
        Builder {
            format_event_kind,
            time_locale,
            max_level,
            make_writer,
        }
    }

    pub fn init(self) -> Result<(), TracingInitError> {
        let Builder {
            format_event_kind,
            time_locale,
            max_level,
            make_writer,
        } = self;

        LogTracer::builder()
            .with_max_level(max_level.as_log())
            .init()?;

        match (format_event_kind, time_locale) {
            (FormatEventKind::AppSimple, TimeLocale::Local) => tracing_init(
                FormatForApp::<Simple, Local>::default(),
                max_level,
                make_writer,
            )?,
            (FormatEventKind::AppSimple, TimeLocale::Utc) => tracing_init(
                FormatForApp::<Simple, Utc>::default(),
                max_level,
                make_writer,
            )?,
            (FormatEventKind::AppDebug, TimeLocale::Local) => tracing_init(
                FormatForApp::<Debug, Local>::default(),
                max_level,
                make_writer,
            )?,
            (FormatEventKind::AppDebug, TimeLocale::Utc) => tracing_init(
                FormatForApp::<Debug, Utc>::default(),
                max_level,
                make_writer,
            )?,
            (FormatEventKind::Server, TimeLocale::Local) => tracing_init(
                FormatForServer::<Local>::default(),
                max_level,
                make_writer,
            )?,
            (FormatEventKind::Server, TimeLocale::Utc) => tracing_init(
                FormatForServer::<Local>::default(),
                max_level,
                make_writer,
            )?,
        };

        Ok(())
    }
}

fn tracing_init<E, W>(
    format_event: E,
    max_level: impl Into<LevelFilter>,
    make_writer: W,
) -> Result<(), SetGlobalDefaultError>
where
    E: FormatEvent<Registry, DefaultFields> + Send + Sync + 'static,
    W: MakeWriter + Send + Sync + 'static,
{
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(max_level)
        .event_format(format_event)
        .with_writer(make_writer)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construct_format_events() {
        let _: FormatForApp<Simple, Local> = FormatForApp::simple();
        let _: FormatForApp<Debug, Local> = FormatForApp::debug();
        let _: FormatForApp<Simple, Utc> = FormatForApp::simple_utc();
        let _: FormatForApp<Debug, Utc> = FormatForApp::debug_utc();
        let _: FormatForServer<Utc> = FormatForServer::default();
    }
}
