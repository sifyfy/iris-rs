mod format_time {
    use tracing_subscriber::fmt::time::{ChronoLocal, ChronoUtc};

    pub type Local = ChronoLocal;
    pub type Utc = ChronoUtc;
}

mod format_fields {}

mod format_event {
    use super::format_time::{Local, Utc};
    use chrono::prelude::*;
    use std::fmt::Write;
    use std::marker::PhantomData;
    use thiserror::private::DisplayAsDisplay;
    use tracing::{Event, Subscriber};
    use tracing_log::NormalizeEvent;
    use tracing_subscriber::fmt::time::FormatTime;
    use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, FormattedFields};
    use tracing_subscriber::registry::LookupSpan;

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
                write!(writer, " ");
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
                    if let Some(fields) = span.extensions()
                        .get::<FormattedFields<N>>() {
                        if !fields.is_empty() {
                            write!(writer, "{{{}}}", fields)?;
                        }
                    }
                    Ok(())
                })?;
                write!(writer, "]")?;
            }
            {
                write!(writer, " ");
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
            // {
            //     write!(writer, "[")?;
            //     self.format_time.format_time(writer)?;
            //     write!(writer, "]")?;
            // }
            // {
            //     let normalized_metadata = event.normalized_metadata();
            //     let metadata = normalized_metadata
            //         .as_ref()
            //         .unwrap_or_else(|| event.metadata());
            //     write!(writer, "[{level}]", level = metadata.level().as_display())?;
            // }
            // {
            //     write!(writer, " ");
            // }
            // {
            //     ctx.format_fields(writer, event)?;
            // }
            writeln!(writer)
        }
    }
}

pub use self::format_event::{Debug, FormatForApp, FormatForServer, Simple};
pub use self::format_time::{Local, Utc};
pub use tracing::{self, debug, error, info, trace, warn, Level};
use tracing_subscriber::fmt::time::FormatTime;

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
