#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VtEndpoint {
    UploadSmall,
    GetLargeUrl,
    ScanLargeFile,
    Analysis,
}
