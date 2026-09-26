use crate::ToolDescriptor;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub const MAX_SCHEMA_BYTES: usize = 256 * 1024;
pub const MAX_ARGUMENT_BYTES: usize = 256 * 1024;
pub const MAX_SCHEMA_DEPTH: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    #[error("tool name is invalid: {0}")]
    InvalidToolName(String),
    #[error("tool descriptor exceeds size limit")]
    DescriptorTooLarge,
    #[error("tool input schema must be a JSON object")]
    InputSchemaNotObject,
    #[error("tool arguments must be a JSON object")]
    ArgumentsNotObject,
    #[error("tool arguments exceed size limit")]
    ArgumentsTooLarge,
    #[error("schema nesting exceeds depth limit")]
    SchemaTooDeep,
    #[error("external JSON Schema reference is not allowed: {0}")]
    ExternalReference(String),
    #[error("invalid JSON Schema: {0}")]
    InvalidSchema(String),
    #[error("tool arguments do not match input schema: {0}")]
    InvalidArguments(String),
    #[error("failed to serialize canonical JSON: {0}")]
    Serialization(String),
}

pub fn validate_tool_descriptor(tool: &ToolDescriptor) -> Result<(), SchemaError> {
    validate_tool_name(&tool.name)?;

    let bytes = serde_json::to_vec(tool)
        .map_err(|error| SchemaError::Serialization(error.to_string()))?;
    if bytes.len() > MAX_SCHEMA_BYTES {
        return Err(SchemaError::DescriptorTooLarge);
    }

    if !tool.input_schema.is_object() {
        return Err(SchemaError::InputSchemaNotObject);
    }

    validate_schema(&tool.input_schema)?;
    if let Some(output_schema) = &tool.output_schema {
        validate_schema(output_schema)?;
    }

    Ok(())
}

pub fn validate_arguments(schema: &Value, arguments: &Value) -> Result<(), SchemaError> {
    if !arguments.is_object() {
        return Err(SchemaError::ArgumentsNotObject);
    }

    let bytes = serde_json::to_vec(arguments)
        .map_err(|error| SchemaError::Serialization(error.to_string()))?;
    if bytes.len() > MAX_ARGUMENT_BYTES {
        return Err(SchemaError::ArgumentsTooLarge);
    }

    validate_schema(schema)?;
    let validator = jsonschema::draft202012::new(schema)
        .map_err(|error| SchemaError::InvalidSchema(error.to_string()))?;
    validator
        .validate(arguments)
        .map_err(|error| SchemaError::InvalidArguments(error.to_string()))
}

pub fn validate_output(schema: &Value, value: &Value) -> Result<(), SchemaError> {
    validate_schema(schema)?;
    let validator = jsonschema::draft202012::new(schema)
        .map_err(|error| SchemaError::InvalidSchema(error.to_string()))?;
    validator
        .validate(value)
        .map_err(|error| SchemaError::InvalidArguments(error.to_string()))
}

pub fn schema_fingerprint(tool: &ToolDescriptor) -> Result<String, SchemaError> {
    let value = serde_json::json!({
        "name": tool.name,
        "inputSchema": tool.input_schema,
        "outputSchema": tool.output_schema,
    });
    fingerprint_value(b"latch-mcp-schema-v1", &value)
}

pub fn descriptor_fingerprint(tool: &ToolDescriptor) -> Result<String, SchemaError> {
    let value = serde_json::json!({
        "name": tool.name,
        "title": tool.title,
        "description": tool.description,
        "inputSchema": tool.input_schema,
        "outputSchema": tool.output_schema,
        "annotations": tool.annotations,
    });
    fingerprint_value(b"latch-mcp-descriptor-v1", &value)
}

pub fn tool_identity_fingerprint(
    provider_fingerprint: &str,
    tool_name: &str,
    schema_fingerprint: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"latch-mcp-tool-identity-v1");
    hash_text(&mut hasher, provider_fingerprint);
    hash_text(&mut hasher, tool_name);
    hash_text(&mut hasher, schema_fingerprint);
    hex::encode(hasher.finalize())
}

fn validate_schema(schema: &Value) -> Result<(), SchemaError> {
    validate_value_bounds(schema, 0)?;
    reject_external_refs(schema)?;

    jsonschema::draft202012::meta::validate(schema)
        .map_err(|error| SchemaError::InvalidSchema(error.to_string()))?;
    jsonschema::draft202012::new(schema)
        .map_err(|error| SchemaError::InvalidSchema(error.to_string()))?;
    Ok(())
}

fn validate_tool_name(name: &str) -> Result<(), SchemaError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(SchemaError::InvalidToolName(name.to_string()));
    }
    Ok(())
}

fn validate_value_bounds(value: &Value, depth: usize) -> Result<(), SchemaError> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(SchemaError::SchemaTooDeep);
    }

    match value {
        Value::Array(values) => {
            for value in values {
                validate_value_bounds(value, depth + 1)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                validate_value_bounds(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn reject_external_refs(value: &Value) -> Result<(), SchemaError> {
    match value {
        Value::Array(values) => {
            for value in values {
                reject_external_refs(value)?;
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                if matches!(key.as_str(), "$ref" | "$dynamicRef") {
                    if let Some(reference) = value.as_str() {
                        if !reference.starts_with('#') {
                            return Err(SchemaError::ExternalReference(reference.to_string()));
                        }
                    }
                }
                reject_external_refs(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn fingerprint_value(domain: &[u8], value: &Value) -> Result<String, SchemaError> {
    let canonical = canonicalize(value);
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|error| SchemaError::Serialization(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort();
            let mut canonical = Map::new();
            for key in keys {
                canonical.insert(key.clone(), canonicalize(&object[key]));
            }
            Value::Object(canonical)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        _ => value.clone(),
    }
}

fn hash_text(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn descriptor(schema: Value) -> ToolDescriptor {
        ToolDescriptor {
            name: "read_file".into(),
            title: None,
            description: Some("Read a file".into()),
            input_schema: schema,
            output_schema: None,
            annotations: None,
        }
    }

    #[test]
    fn schema_fingerprint_is_key_order_independent() {
        let first = descriptor(json!({
            "type":"object",
            "properties":{"path":{"type":"string"},"limit":{"type":"integer"}},
            "required":["path"]
        }));
        let second = descriptor(json!({
            "required":["path"],
            "properties":{"limit":{"type":"integer"},"path":{"type":"string"}},
            "type":"object"
        }));

        assert_eq!(
            schema_fingerprint(&first).expect("fingerprint"),
            schema_fingerprint(&second).expect("fingerprint")
        );
    }

    #[test]
    fn external_schema_references_are_rejected() {
        let tool = descriptor(json!({
            "type":"object",
            "properties":{"path":{"$ref":"https://attacker.example/schema.json"}}
        }));

        assert!(matches!(
            validate_tool_descriptor(&tool),
            Err(SchemaError::ExternalReference(_))
        ));
    }

    #[test]
    fn local_schema_references_are_allowed() {
        let tool = descriptor(json!({
            "type":"object",
            "$defs":{"path":{"type":"string"}},
            "properties":{"path":{"$ref":"#/$defs/path"}}
        }));

        validate_tool_descriptor(&tool).expect("local refs should compile");
    }

    #[test]
    fn arguments_are_validated_against_schema() {
        let tool = descriptor(json!({
            "type":"object",
            "properties":{"path":{"type":"string"}},
            "required":["path"],
            "additionalProperties":false
        }));

        validate_arguments(&tool.input_schema, &json!({"path":"README.md"}))
            .expect("valid arguments");
        assert!(validate_arguments(&tool.input_schema, &json!({"path":42})).is_err());
        assert!(validate_arguments(
            &tool.input_schema,
            &json!({"path":"README.md","extra":true})
        )
        .is_err());
    }
}
