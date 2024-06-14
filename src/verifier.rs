use crate::*;

use async_trait::async_trait;
use crate::signature::ObjSignature;

#[async_trait]
pub trait ObjVerifier: Send + Sync {
    fn public_key(&self) -> &PublicKey;
    async fn verify(&self, data: &[u8], sign: &ObjSignature) -> bool;
}

#[async_trait]
pub trait PublicKeySearch: Send + Sync {
    async fn search_public_key(&self, sign: &ObjSignature) -> BuckyResult<&PublicKey>;
}

#[async_trait]
impl ObjVerifier for Box<dyn ObjVerifier> {
    fn public_key(&self) -> &PublicKey {
        self.as_ref().public_key()
    }

    async fn verify(&self, data: &[u8], sign: &ObjSignature) -> bool {
        self.as_ref().verify(data, sign).await
    }
}
