use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TableRef {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FilterColumn {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    pub column: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder_number: Option<usize>,
    pub is_placeholder: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InsertColumn {
    pub column: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder_number: Option<usize>,
    pub is_placeholder: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueType {
    Literal,
    Placeholder,
    InsertColumnReference,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SetColumn {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub table: Option<String>,
    pub column: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder_number: Option<usize>,
    pub value_type: ValueType,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SqlQueryResult {
    pub kind: String,
    pub tables: Vec<TableRef>,
    pub filters: Vec<FilterColumn>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insert_columns: Option<Vec<Vec<InsertColumn>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub set_columns: Option<Vec<SetColumn>>,
}
