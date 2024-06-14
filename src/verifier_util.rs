use crate::*;

use async_trait::async_trait;
use crate::signature::ObjSignature;
// 提供一个默认签名器实现

pub struct RsaCPUObjectVerifier {
    public_key: PublicKey,
}

impl RsaCPUObjectVerifier {
    pub fn new(public_key: PublicKey) -> RsaCPUObjectVerifier {
        RsaCPUObjectVerifier {
            public_key: public_key,
        }
    }
}

#[async_trait]
impl ObjVerifier for RsaCPUObjectVerifier {
    fn public_key(&self) -> &PublicKey {
        return &self.public_key;
    }

    async fn verify(&self, data: &[u8], sign: &ObjSignature) -> bool {
        self.public_key.verify(data, sign.signature())
    }
}
/*
pub async fn verify_object<D, V, N>(verifier: &V, obj:& N) -> BuckyResult<bool>
    where D: ObjectType,
        D::DescType: RawEncode,
        D::ContentType: RawEncode,
        V: Verifier,
        N: NamedObject<D>,
        N: PublicKeySearch,  // 必须实现Key查找Trait
{
    let ret = verify_object_desc(verifier, obj).await?;
    if !ret {
        return Ok(false);
    }

    let ret = verify_object_body(verifier, obj).await?;
    if !ret {
        return Ok(false);
    }

    Ok(true)
}


pub async fn verify_object_desc<D, V, N>(verifier: &V, obj:& N) -> BuckyResult<bool>
    where D: ObjectType,
        D::DescType: RawEncode,
        D::ContentType: RawEncode,
        V: Verifier,
        N: NamedObject<D>,
        N: PublicKeySearch,  // 必须实现Key查找Trait
{
    let signs = obj.signs().desc_signs().as_ref();
    if signs.is_none() {
        return  Ok(false);
    }

    let signs = signs.unwrap();
    for sign in signs {
        let public_key = obj.search_public_key(sign).await?;
        let ret = verify_object_desc_sign(verifier, obj, public_key, sign).await?;
        if !ret {
            return  Ok(false);
        }
    }

    Ok(true)
}

//TODO：该函数的意义是验证object的body是否有有效的签名，是和对象的类型有关的，我们有如下几种
//  1.有权对象，分Single和MN判断。
//  2.有主对象，根据Owner的类型区分判断。

pub async fn verify_object_body<D, V, N>(verifier: &V, obj:& N) -> BuckyResult<bool>
    where D: ObjectType,
        D::DescType: RawEncode,
        D::ContentType: RawEncode,
        V: Verifier,
        N: NamedObject<D>,
        N: PublicKeySearch,  // 必须实现Key查找Trait
{
    let signs = obj.signs().body_signs().as_ref();
    if signs.is_none() {
        return  Ok(false);
    }

    let signs = signs.unwrap();
    for sign in signs {
        let public_key = obj.search_public_key(sign).await?;
        let ret = verify_object_desc_sign(verifier, obj, public_key, sign).await?;
        if !ret {
            return  Ok(false);
        }
    }

    Ok(true)
}
*/

// 具体每个 NamedObject 应该自己根据 Signature 的 sign_source 取到对应的PublicKey，然后调用本方法验证
pub async fn verify_object_desc_sign<D, V, N>(
    verifier: &V,
    obj: &N,
    sign: &ObjSignature,
) -> BuckyResult<bool>
where
    D: ObjectType,
    D::DescType: RawEncode,
    D::ContentType: RawEncode + BodyContent,
    V: ObjVerifier,
    N: NamedObject<D>,
{
    let hash_value = obj.desc().raw_hash_value()?;

    let ret = verifier.verify(hash_value.as_slice(), sign).await;

    Ok(ret)
}

//TODO：

pub async fn verify_object_body_sign<D, V, N>(
    verifier: &V,
    obj: &N,
    sign: &ObjSignature,
) -> BuckyResult<bool>
where
    D: ObjectType,
    D::DescType: RawEncode,
    D::ContentType: RawEncode + BodyContent,
    V: ObjVerifier,
    N: NamedObject<D>,
{
    let ret = if let Some(body) = obj.body() {
        // Need to check whether body.object_id matches with desc.object_id in the place where check body signature
        if body.object_id().is_some() {
            body.verify_object_id(&obj.desc().object_id())?;
        }

        let hash_value = body.raw_hash_value()?;

        verifier.verify(hash_value.as_slice(), sign).await
    } else {
        // FIXME What should we do with object verify signatures that do not have a body?
        false
    };

    Ok(ret)
}

pub struct AnyNamedObjectVerifyHelper;

impl AnyNamedObjectVerifyHelper {
    pub async fn verify_desc_sign<V>(
        verifier: &V,
        obj: &AnyNamedObject,
        sign: &ObjSignature,
    ) -> BuckyResult<bool>
    where
        V: ObjVerifier,
    {
        let hash_value = obj.desc_hash()?;

        let ret = verifier.verify(hash_value.as_slice(), sign).await;

        Ok(ret)
    }

    pub async fn verify_body_sign<V>(
        verifier: &V,
        obj: &AnyNamedObject,
        sign: &ObjSignature,
    ) -> BuckyResult<bool>
    where
        V: ObjVerifier,
    {
        match obj.has_body()? {
            true => {
                if obj.body_object_id().is_some() {
                    obj.verify_body_object_id(&obj.object_id())?;
                }

                let body_hash = obj.body_hash()?.unwrap();
                let ret = verifier.verify(body_hash.as_slice(), sign).await;

                Ok(ret)
            }
            false => {
                Ok(false)
            }
        }
    }
}
