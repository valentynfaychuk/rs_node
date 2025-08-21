use once_cell::sync::OnceCell;
use std::borrow::Cow;
use tokio::fs::{OpenOptions, create_dir_all};
use tokio::io::AsyncWriteExt;

static ARCHIVER_DIR: OnceCell<String> = OnceCell::new();

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    TokioIo(#[from] tokio::io::Error),
    #[error("once cell {0}")]
    OnceCell(&'static str),
}

pub async fn init(base: &str) -> Result<(), Error> {
    if ARCHIVER_DIR.get().is_some() {
        return Ok(());
    }

    let path = format!("{}/log", base);
    create_dir_all(&path).await?;
    ARCHIVER_DIR.set(path).map_err(|_| Error::OnceCell("archiver_dir_set"))?;

    Ok(())
}

pub async fn store<'a>(
    data: impl Into<Cow<'a, [u8]>>,
    subdir: impl AsRef<str>,
    name: impl AsRef<str>,
) -> Result<(), Error> {
    let bin: Cow<[u8]> = data.into();
    let base = ARCHIVER_DIR.get().ok_or(Error::OnceCell("archiver_dir_get"))?;

    let path = if subdir.as_ref().is_empty() {
        format!("{}/{}", base, name.as_ref())
    } else {
        create_dir_all(&format!("{}/{}", base, subdir.as_ref())).await?;
        format!("{}/{}/{}", base, subdir.as_ref(), name.as_ref())
    };

    let mut file = OpenOptions::new().create(true).append(true).open(&path).await?;
    file.write_all(&bin).await?;
    file.flush().await?;

    Ok(())
}
