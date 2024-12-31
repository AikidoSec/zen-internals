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
    fn test_queries_different_but_singleline_comments_same() {
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

    #[test]
    fn test_multiline_comments_in_same_order_and_length() {
        not_comments_changed!("SELECT /*Comment 1*/ COUNT(*) AS total_employees/*Commentz*/ FROM employees;/* hello */", "/*Comment 1*/ SELECT name FROM employees WHERE department =/*Commentz*/ 'Marketing';/* hello */");
        not_comments_changed!(
            "/**/UPDATE employees/*1*/ SET salary = salary * 1.05 WHERE id = 1;",
            "DELETE FROM employees WHERE job_title = 'Intern';/**/ /*1*/"
        );
        not_comments_changed!("/*Comment1*//*Comment2*/INSERT INTO employees (name, job_title, salary) VALUES ('Jane Smith', 'Developer', 75000);", "SELECT DISTINCT job_title FROM employees;/*Comment1*//*Comment2*/");
    }

    #[test]
    fn test_multiline_comments_changed() {
        // Comments remain the same but different order :
        comments_changed!(
            "SELECT /*123*/ FROM /*1234*/",
            "SELECT /*1234*/ FROM /*123*/"
        );
        comments_changed!(
            "SELECT /* Holla! */ FROM /*Mi Amigos*/",
            "SELECT /*Mi Amigos*/ FROM /* Holla! */"
        );

        // Exactly the same comment but count is different :
        comments_changed!("SELECT /*1*/; FROM /*1*/;", "SELECT /*1*/ FROM --1");
        comments_changed!("SELECT /*1*/; FROM /*1*/;", "SELECT /*1*/ FROM");
        comments_changed!("SELECT /*1*/; FROM;", "SELECT /*1*/; FROM /*1*/;");
        comments_changed!("SELECT /**/; FROM /**/;", "SELECT /**/ FROM");
        comments_changed!(
            "SELECT /*  Hello World!  */; FROM /*  Hello World!  */;/*  Hello World!  */",
            "SELECT /*  Hello World!  */ FROM /*  Hello World!  */"
        );

        // Comments differ in length but not position :
        comments_changed!(
            "SELECT /*12345*/ FROM /*123456*/",
            "SELECT /*12345*/ FROM /*1234*/"
        );
    }

    #[test]
    fn test_singleline_comments_changed() {
        // Comments remain the same but different order :
        comments_changed!(
            "SELECT --123;
            FROM --1234",
            "SELECT --1234;
            FROM --123"
        );
        comments_changed!(
            "SELECT -- Holla!
            FROM --Mi Amigos",
            "SELECT --Mi Amigos
            FROM -- Holla!"
        );

        // Exactly the same comment but count is different :
        comments_changed!(
            "SELECT --1;
            FROM /*1*/ --1;",
            "SELECT --1;
            FROM --1;
            --1;"
        );

        // Comments differ in length but not position :
        comments_changed!(
            "--1234
            --123456
            --12",
            "--123
            --123456
            --12"
        );
    }

    #[test]
    fn test_singleline_comments_different_prefix() {
        not_comments_changed!("COUNT # Hello!", "SELECT * FROM # Hello!");
        comments_changed!("COUNT -- Hello", "COUNT # Hello");
    }

    #[test]
    fn test_combination_multiline_and_singleline() {
        comments_changed!("SELECT /*1*/; FROM /*1*/;", "SELECT /*1*/ FROM --1");
        comments_changed!(
            "SELECT --1;
            FROM /*1*/ --1;",
            "SELECT --1;
            FROM --1;"
        );
    }
}
