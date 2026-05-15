use std::sync::LazyLock;

use tokio::runtime::{Builder, Runtime};

pub(crate) static RUNTIME: LazyLock<anyhow::Result<Runtime>> = LazyLock::new(|| {
    Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .thread_name("tacacsrs-bash-plugin-ipc")
        .build()
        .map_err(Into::into)
});
