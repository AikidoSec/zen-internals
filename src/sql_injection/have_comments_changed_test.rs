#[cfg(test)]
mod tests {
    use crate::sql_injection::have_comments_changed::have_comments_changed;
    use crate::sql_injection::tokenize_query::tokenize_query;

    macro_rules! comments_changed {
        ($query1:expr, $query2:expr) => {
            let tokens1 = tokenize_query($query1, 0);
            let tokens2 = tokenize_query($query2, 0);
            assert!(have_comments_changed(tokens1, tokens2))
        };
    }

    macro_rules! not_comments_changed {
        ($query1:expr, $query2:expr) => {
            let tokens1 = tokenize_query($query1, 0);
            let tokens2 = tokenize_query($query2, 0);
            assert!(!have_comments_changed(tokens1, tokens2))
        };
    }

}
