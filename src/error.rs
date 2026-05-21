use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ContainerError {
    #[error("process args is empty")]
    EmptyProcessArgs,

    #[error("missing required process config field: {field}")]
    MissingProcessConfigField { field: &'static str },

    #[error("pty slave is closed")]
    PtySlaveClosed,
}
