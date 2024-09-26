macro_rules! comments_changed {
    ($query1:expr, $query2:expr) => {
        let tokens1 = tokenize_query($query1, 0);
        let tokens2 = tokenize_query($query2, 0);
        assert!(check_comments_changed(tokens1, tokens2))
    };
}
macro_rules! not_comments_changed {
    ($query1:expr, $query2:expr) => {
        let tokens1 = tokenize_query($query1, 0);
        let tokens2 = tokenize_query($query2, 0);
        assert!(!check_comments_changed(tokens1, tokens2))
    };
}
#[cfg(test)]
mod tests {
    use crate::sql_injection::check_comments_changed::check_comments_changed;
    use crate::sql_injection::tokenize_query::tokenize_query;

    #[test]
    fn test_queries_with_no_comments_not_compared() {
        not_comments_changed!("SELECT AVG(salary) AS average_salary FROM employees;", "INSERT INTO employees (name, position, salary) VALUES ('John Doe', 'Software Engineer', 70000);");
        not_comments_changed!(
            "DELETE FROM employees WHERE job_title = 'Intern';",
            "CREATE TABLE departments (
                id INT PRIMARY KEY AUTO_INCREMENT,
                name VARCHAR(100) NOT NULL,
                location VARCHAR(100)
            );"
        );
        not_comments_changed!(
            "UPDATE employees SET salary = salary * 1.10 WHERE department = 'Sales';",
            "SELECT DISTINCT job_title FROM employees;"
        );
    }

    #[test]
    fn test_quries_different_but_singleline_comments_same() {
        not_comments_changed!("SELECT AVG(salary) AS average_salary FROM employees; -- hewwo", "INSERT INTO employees (name, position, salary) VALUES ('John Doe', 'Software Engineer', 70000); -- hewwo");
        not_comments_changed!(
            "DELETE FROM employees WHERE job_title = 'Intern';  --   Bonjorno    ",
            "CREATE TABLE departments (
                id INT PRIMARY KEY AUTO_INCREMENT,
                name VARCHAR(100) NOT NULL,
                location VARCHAR(100)
            );--   Bonjorno    "
        );
        not_comments_changed!(
            "UPDATE employees SET salary = salary * 1.10 WHERE department = 'Sales';--Ciao",
            "SELECT DISTINCT job_title FROM employees; --Ciao"
        );
        not_comments_changed!(
            "UPDATE employees SET salary = salary * 1.10;--Ciao; 
            HERE department = 'Sales' -- Hello",
            "SELECT DISTINCT job_title FROM employees; --Ciao; 
            -- Hello"
        );
    }
}
