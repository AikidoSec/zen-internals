#[cfg(test)]
mod tests {
    use crate::js_injection::detect_js_injection::detect_js_injection_str;

    macro_rules! is_injection {
        ($code:expr, $input:expr, $sourcetype:expr) => {
            assert!(detect_js_injection_str(
                &$code.to_lowercase(),
                &$input.to_lowercase(),
                $sourcetype
            ))
        };
    }

    macro_rules! not_injection {
        ($code:expr, $input:expr, $sourcetype:expr) => {
            assert!(!detect_js_injection_str(
                &$code.to_lowercase(),
                &$input.to_lowercase(),
                $sourcetype
            ))
        };
    }

    #[test]
    fn test_cjs_const() {
        not_injection!("const test = 'Hello World!';", "Hello World!", 0);
        is_injection!("const test = 'Hello World!'; //';", "Hello World!'; //", 0);
        is_injection!(
            "const test = 'Hello World!';console.log('Injected!'); //';",
            "Hello World!';console.log('Injected!'); //",
            0
        );
        is_injection!(
            "const test = 'Hello World!'; console.log('injection'); // This is a comment'; // Test",
            "Hello World!'; console.log('injection'); // This is a comment",
            0
        );
        is_injection!(
            "const test = 'Hello World!'; // This is a comment'; // Test",
            "Hello World!'; // This is a comment",
            0
        );
    }

    #[test]
    fn test_cjs_if() {
        not_injection!("if (true) { return true; }", "true", 0);
        not_injection!("if (1 > 5) { return true; }", "5", 0);
        is_injection!(
            "if(username === 'admin' || 1 === 1) { return true; } //');",
            "admin' || 1 === 1) { return true; } //",
            0
        );
        not_injection!(
            "if(username === 'admin' || 1 === 1) { return true; }",
            "admin",
            0
        );
        is_injection!(
            "if (username === 'admin' || 1 === 1) { return true; } //') {}",
            "admin' || 1 === 1) { return true; } //",
            0
        );
        is_injection!("if (1 > 5 || 1 === 1) { return true; }", "5 || 1 === 1", 0);
    }

    #[test]
    fn mongodb_js() {
        not_injection!("this.name === 'a' && sleep(2000) && 'b'", "a", 0);
        not_injection!("this.group === 1", "1", 0);
        is_injection!(
            "this.name === 'a' && sleep(2000) && 'b'",
            "a' && sleep(2000) && 'b",
            0
        );
        is_injection!("const test = this.group === 1 || 1 === 1;", "1 || 1 ===", 0);
    }

    #[test]
    fn test_cjs_function() {
        not_injection!("function test() { return 'Hello'; }", "Hello", 0);
        not_injection!("test(\"arg1\", 0, true);", "arg1", 0);
        is_injection!(
            "function test() { return 'Hello'; } //';}",
            "Hello'; } //",
            0
        );
        is_injection!(
            "test(\"arg1\", 12, true); // \", 0, true);",
            "arg1\", 12, true); // ",
            0
        );
    }

    #[test]
    fn test_cjs_object() {
        not_injection!("const obj = { test: 'value', isAdmin: true };", "value", 0);
        is_injection!(
            "const obj = { test: 'value', isAdmin: true }; //'};",
            "value', isAdmin: true }; //",
            0
        );
        not_injection!("const obj = [1, 2, 3];", "1", 0);
        not_injection!("const obj = { test: [1, 2, 3] };", "1", 0);
        not_injection!("const obj = { test: [1, 4, 2, 3] };", "1, 4", 0);
        is_injection!(
            "const obj = { test: [1, 4], test2: [2, 3] };",
            "1, 4], test2: [2, 3",
            0
        );
    }

    #[test]
    fn test_ts_code() {
        not_injection!("const obj: string = 'Hello World!';", "Hello World!", 1);
        is_injection!(
            "const obj: string = 'Hello World!'; console.log('Injected!'); //';",
            "Hello World!'; console.log('Injected!'); //",
            1
        );
        not_injection!("function test(): string { return 'Hello'; }", "Hello", 1);
        is_injection!(
            "function test(): string { return 'Hello'; } //';}",
            "Hello'; } //",
            1
        );
        // Not an injection because code can not be parsed as JavaScript.
        not_injection!(
            "function test(): string { return 'Hello'; } //';}",
            "Hello'; } //",
            0
        );
    }

    #[test]
    fn test_import() {
        for sourcetype in 0..5 {
            not_injection!(
                "import { test } from 'module'; test('Hello');",
                "Hello",
                sourcetype
            );
            is_injection!(
                "import { test } from 'module'; test('Hello'); console.log('Injected!'); //');",
                "Hello'); console.log('Injected!'); //",
                sourcetype
            );
        }
    }

    #[test]
    fn test_no_js_injection() {
        not_injection!("Hello World!", "Hello World!", 0);
        not_injection!("", "", 0);
        not_injection!("", "Hello World!", 0);
        not_injection!("Hello World!", "", 0);
        not_injection!("const test = 123;", "123", 0);
        not_injection!("// Reason: Test", "Test", 0);
    }

    #[test]
    fn invalid_js_without_userinput() {
        // Previously the double-fail fallback (both replacement and removal cause parse errors)
        // returned false unconditionally. The fix detects structural JS elements instead.
        // This input contains ";" and IS a real injection — correctly flagged now.
        is_injection!(
            "const test = 'Hello World!'; console.log('Injected!');",
            "Hello World!'; console.log('Injected!');",
            0
        );
    }

    #[test]
    fn test_ternary_injection_bypass() {
        is_injection!("10 ? process.version : 5", "? process.version :", 0);
        is_injection!("10 ? process.env.path : 5", "? process.env.path :", 0);
    }

    #[test]
    fn test_structural_injection_bypass() {
        is_injection!(
            "if (x) { dosomething() } else { console.log('injected') }",
            "} else { console.log('injected') }",
            0
        );
        is_injection!(
            "arr.sort((a, b) => evil() - b.field)",
            "=> evil() - b.field",
            0
        );
        is_injection!(
            "10 ; console.log('injected') ; 5",
            "; console.log('injected') ;",
            0
        );
        is_injection!("try { a() } catch (e) { evil() }", "catch", 0);

        // Word-boundary check
        not_injection!("const catchError = 5;", "catchError", 0);
    }

    #[test]
    fn test_js_allow_math() {
        not_injection!("const test = 1 + 2;", "1 + 2", 0);
        not_injection!("const test = 5 / 6 + 2;", "5 / 6 + 2", 0);
        not_injection!("const test = 5 % 2 + 5.6;", "5 % 2 + 5.6", 0);
    }

    #[test]
    fn test_js_real_cve() {
        // CVE-2024-21511
        is_injection!(
            "packet.readDateTimeString('abc'); process.exit(1); // ');",
            "abc'); process.exit(1); //",
            0
        );
        // GHSA-q849-wxrc-vqrp
        is_injection!(
            "const o = {}; o['x']= pt[0]; o['y']=1; process.exit(); return o;",
            "1; process.exit()",
            0
        );
        not_injection!("const o = {}; o['x']= pt[0]; o['y']=2; return o;", "2", 2);
        // CVE-2021-21278
        is_injection!(
            "const window={}; alert('!'); return window.__NUXT__",
            "alert('!');",
            0
        );
        // CVE-2023-34232
        is_injection!(
            "(\"[]\"); fetch('https://example.com/'); // \");",
            "[]\"); fetch('https://example.com/'); //",
            0
        );
        // CVE-2023-1283
        is_injection!(
            "(() => {
                console.log(\"[+] Qwik RCE demo, by ohb00.\")
                process.binding('spawn_sync').spawn({
                    file: 'C:\\Windows\\System32\\cmd.exe',
                    args: [
                        'cmd', '/c', 'calc.exe'
                    ],
                    stdio: [
                        {type:'pipe',readable:!0,writable:!1},
                        {type:'pipe',readable:!1,writable:!0},
                        {type:'pipe',readable:!1,writable:!0}

                    ]
                })
                return {}
            })()",
            "(() => {
                console.log(\"[+] Qwik RCE demo, by ohb00.\")
                process.binding('spawn_sync').spawn({
                    file: 'C:\\Windows\\System32\\cmd.exe',
                    args: [
                        'cmd', '/c', 'calc.exe'
                    ],
                    stdio: [
                        {type:'pipe',readable:!0,writable:!1},
                        {type:'pipe',readable:!1,writable:!0},
                        {type:'pipe',readable:!1,writable:!0}

                    ]
                })
                return {}
            })()",
            0
        )
    }

    #[test]
    fn test_js_return_without_function() {
        is_injection!(
            "return 'test'; console.log('injection'); //';",
            "test'; console.log('injection'); //",
            0
        );
    }

    #[test]
    fn test_ternary_bypass_variants() {
        is_injection!("score > 0 ? data.value : defaultValue", "? data.value :", 0);
        is_injection!("count > 0 ? result.output : null", "? result.output :", 0);
        is_injection!("isValid ? user.role : guestRole", "? user.role :", 0);
        is_injection!(
            "enabled ? config.setting : defaults.setting",
            "? config.setting :",
            0
        );
        is_injection!(
            "input > threshold ? response.data : fallback",
            "? response.data :",
            0
        );
        for sourcetype in 0..5 {
            is_injection!(
                "active ? user.token : session.token",
                "? user.token :",
                sourcetype
            );
        }
    }

    #[test]
    fn test_block_bridge_variants() {
        is_injection!(
            "try { db.query(sql) } catch (err) { logger.error(err) }",
            "} catch (err) { logger.error(err) }",
            0
        );
        is_injection!(
            "try { fs.writeFile(path, data) } finally { fd.close() }",
            "} finally { fd.close() }",
            0
        );
        is_injection!(
            "if (user.isAdmin) { renderDashboard() } else { renderLogin() }",
            "} else { renderLogin() }",
            0
        );
        is_injection!(
            "if (status === 'ok') { resolve(data) } else if (status === 'retry') { retry() }",
            "} else if (status === 'retry') { retry() }",
            0
        );
        is_injection!(
            "try { db.query(sql) } catch (err) { rollback() } finally { db.close() }",
            "} catch (err) { rollback() } finally { db.close() }",
            0
        );
        is_injection!("try { connect(host) } finally { cleanup() }", "finally", 0);
        is_injection!("try { connect() } catch { disconnect() }", " catch", 0);
        is_injection!(
            "try { connect(host) } catch (err) { handleError(err) }",
            "catch (err)",
            0
        );
    }

    #[test]
    fn test_for_loop_bridge() {
        is_injection!(
            "for (let index = 0; index < items.length; index++) { processItem(index) }",
            "; index < items.length; index++) { processItem(index) }",
            0
        );
        is_injection!(
            "for (let row = 0; row < matrix.rows; row++) { renderRow(row) }",
            "; row < matrix.rows; row++) { renderRow(row) }",
            0
        );
    }

    #[test]
    fn test_not_injection_string_special_chars() {
        not_injection!(
            "const apiUrl = 'https://api.example.com/search?query=hello&limit=10';",
            "https://api.example.com/search?query=hello&limit=10",
            0
        );
        not_injection!(
            "const template = 'Hello {name}, your score is {score}!';",
            "Hello {name}, your score is {score}!",
            0
        );
        not_injection!(
            "const question = 'What is the capital of France?';",
            "What is the capital of France?",
            0
        );
        not_injection!(
            "const description = 'Maps values using x => x + 1 syntax';",
            "Maps values using x => x + 1 syntax",
            0
        );
        not_injection!(
            "const steps = 'validateInput; sanitize; persist';",
            "validateInput; sanitize; persist",
            0
        );
        not_injection!(
            "const hint = 'Use } else { to add a fallback branch';",
            "Use } else { to add a fallback branch",
            0
        );
        not_injection!(
            "const note = 'Wrap in } catch (err) { to handle errors';",
            "Wrap in } catch (err) { to handle errors",
            0
        );
        not_injection!(
            "const snippet = 'finally => cleanup is not valid syntax';",
            "finally => cleanup is not valid syntax",
            0
        );
        not_injection!(
            "const example = 'case 1: return true;';",
            "case 1: return true;",
            0
        );
    }

    #[test]
    fn test_keyword_word_boundary() {
        not_injection!(
            "const catchError = (err) => handleError(err);",
            "catchError",
            0
        );
        not_injection!("const doSomething = () => processData();", "doSomething", 0);
        not_injection!("const finallyDone = checkCompletion();", "finallyDone", 0);
        not_injection!("const catchphrase = getBrandSlogan();", "catchphrase", 0);
        not_injection!("const elseWhere = getAlternateLocation();", "elseWhere", 0);
        not_injection!("const testCaseId = generateTestId();", "testCaseId", 0);
        not_injection!("const catchAll = createFallbackHandler();", "catchAll", 0);
    }

    #[test]
    fn test_statement_injection_normal_path() {
        is_injection!(
            "const limit = 100; const offset = 0;",
            "100; const offset = 0",
            0
        );
        is_injection!(
            "const config = loadConfig(); module.exports = config;",
            "loadConfig(); module.exports = config",
            0
        );
        is_injection!(
            "users.map(user => user.isActive && sendNotification(user))",
            "=> user.isActive && sendNotification(user)",
            0
        );
        is_injection!(
            "const width = 800; const height = 600; const depth = 32;",
            "800; const height = 600; const depth = 32",
            0
        );
        is_injection!(
            "this.status === 'ok' && handleSuccess() && 'done'",
            "ok' && handleSuccess() && '",
            0
        );
    }

    #[test]
    fn test_js_html_like_comments() {
        not_injection!(
            "const test = '<!-- Hello World! -->';",
            "<!-- Hello World! -->",
            0
        );

        is_injection!(
            "const test = 'a'; <!--\n console.log('injection'); //';",
            "a'; <!--\n console.log('injection'); //",
            2
        );
        is_injection!(
            "const test = 'a'; <!-- Test --> console.log('injection'); //';",
            "a'; <!-- Test --> console.log('injection'); //",
            2
        );
        is_injection!(
            "const test = 'a'; <!-- Test --> console.log('injection'); //';",
            "a'; <!-- Test --> console.log('injection'); //",
            0
        );
        is_injection!(
            "const test = 'a'; <!--\n console.log('injection'); //';",
            "a'; <!--\n console.log('injection'); //",
            0
        );

        // ESM does not support HTML-like comments.
        not_injection!(
            "const test = 'a'; <!--\n console.log('injection'); //';",
            "a'; <!--\n console.log('injection'); //",
            3
        );
    }
}
