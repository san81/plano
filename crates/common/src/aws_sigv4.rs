use crate::errors::AwsError;
use std::collections::BTreeMap;
use std::time::SystemTime;

pub struct SigV4Params {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    pub region: String,
    pub service: String,
    pub method: String,
    pub uri: String,
    pub query_string: String,
    pub headers: BTreeMap<String, String>,
    pub payload: Vec<u8>,
    pub signing_time: Option<SystemTime>,
}

#[cfg(feature = "aws-sigv4")]
mod aws_impl {
    use super::{AwsError, SigV4Params};
    use aws_credential_types::Credentials;
    use aws_sigv4::http_request::{SignableRequest, SigningParams, SigningSettings, Signer};
    use aws_types::region::Region;
    use bytes::Bytes;
    use http::Request;
    use std::time::SystemTime;

    pub fn sign_request(params: SigV4Params) -> Result<(String, String, String), AwsError> {
        let creds = Credentials::new(
            params.access_key_id,
            params.secret_access_key,
            params.session_token,
            None,
            "plano",
        );

        let region = Region::new(params.region);
        let settings = SigningSettings::default();
        let now = params.signing_time.unwrap_or_else(SystemTime::now);

        let uri = if params.query_string.is_empty() {
            params.uri.clone()
        } else {
            format!("{}?{}", params.uri, params.query_string)
        };

        let host = params
            .headers
            .get("host")
            .ok_or_else(|| AwsError::SigningError("Host header not found".to_string()))?
            .clone();

        let mut builder = Request::builder()
            .method(params.method.as_str())
            .uri(uri)
            .header("host", host);

        for (k, v) in &params.headers {
            builder = builder.header(k.as_str(), v.as_str());
        }

        let req = builder
            .body(Bytes::from(params.payload))
            .map_err(|e| AwsError::SigningError(format!("build request failed: {e}")))?;

        let signable = SignableRequest::from(&req);
        let signing_params = SigningParams::builder()
            .access_key(creds)
            .region(region)
            .service_name(&params.service)
            .settings(settings)
            .time(now)
            .build()
            .map_err(|e| AwsError::SigningError(format!("signing params error: {e}")))?;

        let signer = Signer::new();
        let output = signer
            .sign(signable, &signing_params)
            .map_err(|e| AwsError::SigningError(format!("signing failed: {e}")))?;

        let mut signed_req = req;
        output
            .signing_instructions
            .apply_to_request_http1x(&mut signed_req);

        let authorization = signed_req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let amz_date = signed_req
            .headers()
            .get("x-amz-date")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        let signature = extract_signature(&authorization);

        Ok((authorization, amz_date, signature))
    }

    fn extract_signature(authorization: &str) -> String {
        authorization
            .split("Signature=")
            .nth(1)
            .unwrap_or("")
            .trim()
            .to_string()
    }
}

#[cfg(feature = "aws-sigv4")]
pub use aws_impl::sign_request;

#[cfg(not(feature = "aws-sigv4"))]
pub fn sign_request(_params: SigV4Params) -> Result<(String, String, String), AwsError> {
    Err(AwsError::SigningError(
        "aws-sigv4 feature disabled".to_string(),
    ))
}

#[cfg(all(test, feature = "aws-sigv4"))]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn test_sigv4_signing_fixed_time_scope() {
        let mut headers = BTreeMap::new();
        headers.insert("host".to_string(), "example.amazonaws.com".to_string());

        let (authorization, amz_date, _signature) = sign_request(SigV4Params {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
            region: "us-east-1".to_string(),
            service: "service".to_string(),
            method: "GET".to_string(),
            uri: "/test.txt".to_string(),
            query_string: "X=Y".to_string(),
            headers,
            payload: Vec::new(),
            signing_time: Some(UNIX_EPOCH + Duration::from_secs(0)),
        })
        .expect("signing failed");

        assert_eq!(amz_date, "19700101T000000Z");
        assert!(authorization.contains("AWS4-HMAC-SHA256"));
        assert!(authorization.contains(
            "Credential=AKIDEXAMPLE/19700101/us-east-1/service/aws4_request"
        ));
        assert!(authorization.contains("SignedHeaders=host"));
    }

    #[test]
    fn test_sigv4_official_iam_list_users_vector() {
        // AWS General Reference SigV4 example (IAM ListUsers)
        // https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
        let mut headers = BTreeMap::new();
        headers.insert(
            "content-type".to_string(),
            "application/x-www-form-urlencoded; charset=utf-8".to_string(),
        );
        headers.insert("host".to_string(), "iam.amazonaws.com".to_string());

        let (authorization, amz_date, _signature) = sign_request(SigV4Params {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
            region: "us-east-1".to_string(),
            service: "iam".to_string(),
            method: "GET".to_string(),
            uri: "/".to_string(),
            query_string: "Action=ListUsers&Version=2010-05-08".to_string(),
            headers,
            payload: Vec::new(),
            signing_time: Some(UNIX_EPOCH + Duration::from_secs(1440938160)),
        })
        .expect("signing failed");

        assert_eq!(amz_date, "20150830T123600Z");
        assert_eq!(
            authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }

    #[test]
    fn test_sigv4_query_ordering_is_canonicalized() {
        let mut headers = BTreeMap::new();
        headers.insert("host".to_string(), "iam.amazonaws.com".to_string());

        let params_base = SigV4Params {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
            region: "us-east-1".to_string(),
            service: "iam".to_string(),
            method: "GET".to_string(),
            uri: "/".to_string(),
            query_string: "b=2&a=1".to_string(),
            headers: headers.clone(),
            payload: Vec::new(),
            signing_time: Some(UNIX_EPOCH + Duration::from_secs(1440938160)),
        };

        let mut params_sorted = params_base.clone();
        params_sorted.query_string = "a=1&b=2".to_string();

        let (auth_unsorted, _date1, _sig1) = sign_request(params_base).expect("signing failed");
        let (auth_sorted, _date2, _sig2) = sign_request(params_sorted).expect("signing failed");

        assert_eq!(auth_unsorted, auth_sorted);
    }
}
