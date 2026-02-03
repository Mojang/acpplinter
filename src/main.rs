mod log_output;

use async_std::fs::File;
use async_std::io::prelude::*;
use clap::{App, Arg};
use futures::future;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::env;
use std::fmt;
use std::fs::File as SyncFile;
use std::path::{Path, PathBuf};
use std::process;
use walkdir::WalkDir;

fn to_absolute_path(path: &Path) -> Result<PathBuf, std::io::Error> {
    let canonical = std::fs::canonicalize(path)?;
    if canonical.is_absolute() {
        return Ok(canonical);
    }

    let mut root = std::env::current_dir()?;
    root.push(&canonical);
    Ok(root)
}

fn to_single_regex(strings: &[String]) -> Option<Regex> {
    if strings.is_empty() {
        return None;
    }
    let mut full_regex_string = String::new();
    for string in strings {
        if !full_regex_string.is_empty() {
            full_regex_string.push('|');
        }
        full_regex_string.push_str(string);
    }

    Some(Regex::new(&full_regex_string).unwrap())
}

fn to_unix_string(path: &Path) -> Cow<'_, str> {
    let mut string = path.to_string_lossy();

    if string.as_ref().find('\\').is_some() {
        string = Cow::Owned(string.as_ref().replace("\\", "/"));
    }

    string
}

fn matches_maybe(path: &Path, regex: &Option<Regex>) -> bool {
    if let Some(r) = regex {
        return r.is_match(&to_unix_string(path));
    }
    false
}

struct Info<'a> {
    path: PathBuf,
    line: Option<usize>,
    snippet: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct Warning {
    path: PathBuf,
    line: Option<usize>,
    snippet: Option<String>,
    blame: Option<String>,
}

impl Warning {
    fn new(info: &Info) -> Self {
        Warning {
            path: info.path.clone(),
            line: info.line,
            blame: None,
            snippet: match info.snippet {
                Some(snippet) => Some(snippet.to_owned()),
                None => None,
            },
        }
    }
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(ref blame) = self.blame {
            write!(f, "{}\t\t{}", blame, self.snippet.as_ref().unwrap()) //snippet must exist if there is a blame
        } else if let Some(ref line) = self.line {
            write!(
                f,
                "{}({}): error :\t\t{}",
                dunce::canonicalize(&self.path).unwrap().display(),
                line,
                self.snippet.as_ref().unwrap() //snippet must exist if there is a line
            )
        } else {
            write!(f, "{}", self.path.display())
        }
    }
}

#[derive(Default)]
struct Warnings {
    map: HashMap<String, Vec<Warning>>,
}

impl Warnings {
    fn add(&mut self, message: &str, info: &Info) {
        if !self.map.contains_key(message) {
            self.map
                .insert(message.to_owned(), vec![Warning::new(info)]);
        } else {
            self.map.get_mut(message).unwrap().push(Warning::new(info));
        }
    }

    fn add_map(&mut self, other: Warnings) {
        for (k, mut v) in other.map {
            self.map.entry(k).or_insert_with(Vec::new).append(&mut v);
        }
    }

    fn len(&self) -> usize {
        self.map.len()
    }
}

impl fmt::Display for Warnings {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (k, v) in &self.map {
            writeln!(f, "\nLinter: error : #### {}\n", k).unwrap();

            for warning in v {
                writeln!(f, "{}", warning).unwrap();
            }
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct JsonWarning {
    error: String,
    path: PathBuf,
    line: Option<usize>,
    snippet: Option<String>,
    blame: Option<String>,
}

#[derive(Serialize)]
struct JsonOutput {
    total_issues: usize,
    warnings: Vec<JsonWarning>,
}

impl Warnings {
    fn to_json(&self) -> String {
        let mut json_warnings = Vec::new();
        for (error, warnings) in &self.map {
            for w in warnings {
                json_warnings.push(JsonWarning {
                    error: error.clone(),
                    path: w.path.clone(),
                    line: w.line,
                    snippet: w.snippet.clone(),
                    blame: w.blame.clone(),
                });
            }
        }
        let output = JsonOutput {
            total_issues: json_warnings.len(),
            warnings: json_warnings,
        };
        serde_json::to_string_pretty(&output).unwrap()
    }
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
struct ExpectedFailsDesc {
    exactly: u32,
    //TODO greater than and less than?
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
struct TestDesc {
    fail: Vec<String>,
    allow: Option<Vec<String>>,
    error: String,
    classOnly: Option<bool>,
    headerOnly: Option<bool>,
    include_paths: Option<Vec<String>>,
    exclude_paths: Option<Vec<String>>,
    expected_fails: Option<ExpectedFailsDesc>,
}

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
#[allow(dead_code)]
struct ConfigDesc {
    roots: Vec<String>,
    excludes: Option<Vec<String>>,
    includes: Option<Vec<String>>,
    removeStrings: Option<bool>,
    removeComments: Option<bool>,
    tests: Vec<TestDesc>,
    safeTag: Option<String>,

    // note: this is unused and it's just there for retrocompatibility
    incremental: Option<bool>,
}

#[derive(Clone)]
struct Test {
    fail: Regex,
    allow: Option<Regex>,
    error: String,
    class_only: bool,
    header_only: bool,
    include_paths: Option<Regex>,
    exclude_paths: Option<Regex>,
    expected_fails: ExpectedFailsDesc,
}

impl Test {
    fn from_desc(desc: TestDesc) -> Self {
        Test {
            fail: to_single_regex(&desc.fail).unwrap(),
            allow: to_single_regex(&desc.allow.unwrap_or_default()),
            error: desc.error.clone(),
            class_only: desc.classOnly.unwrap_or(false),
            header_only: desc.headerOnly.unwrap_or(false),
            include_paths: to_single_regex(&desc.include_paths.unwrap_or_default()),
            exclude_paths: to_single_regex(&desc.exclude_paths.unwrap_or_default()),
            expected_fails: desc.expected_fails.unwrap_or_default(),
        }
    }

    fn runs_on_path(&self, path: &Path) -> bool {
        //if there is a special include path, it must match
        let has_include = self.include_paths.is_some();
        if has_include && !matches_maybe(path, &self.include_paths) {
            return false;
        }

        //if there is a special exclude path, it must *not* match
        if matches_maybe(path, &self.exclude_paths) {
            return false;
        }

        true
    }

    fn run(&self, line: &str, header: bool, class: bool) -> bool {
        if (self.class_only && !class) || (self.header_only && !header) {
            return false;
        }

        if self.fail.is_match(line) {
            if let Some(ref a) = self.allow {
                if a.is_match(line) {
                    return false;
                }
            }
            return true;
        }
        false
    }
}

#[derive(Clone)]
struct Config {
    roots: Vec<String>,
    excludes: Option<Regex>,
    includes: Option<Regex>,
    remove_strings: bool,
    remove_comments: bool,
    tests: Vec<Test>,
    safe_tag_regex: Regex,

    class_regex: Regex,
}

impl Config {
    fn from_desc(desc: ConfigDesc) -> Self {
        Config {
            roots: desc.roots,
            excludes: to_single_regex(&desc.excludes.unwrap_or_default()),
            includes: to_single_regex(&desc.includes.unwrap_or_default()),
            remove_strings: desc.removeStrings.unwrap_or(true),
            remove_comments: desc.removeComments.unwrap_or(true),
            tests: desc.tests.into_iter().map(Test::from_desc).collect(),
            safe_tag_regex: Regex::new(".*/\\*\\s*safe\\s*\\*/.*(\\r\\n|\\r|\\n)").unwrap(),
            class_regex: Regex::new("(^|\\s)+class\\s+[^;]*$").unwrap(),
        }
    }

    fn should_check(&self, path: &Path) -> bool {
        matches_maybe(&path, &self.includes) && !matches_maybe(&path, &self.excludes)
    }
}

fn is_newline(c: u8) -> bool {
    c == b'\n' || c == b'\r'
}

fn lookahead_delim(bytes: &[u8], delim: &[u8], start_idx: usize) -> bool {
    for j in 0..delim.len() {
        if bytes[start_idx + j] != delim[j] {
            return false;
        }
    }
    true
}

fn remove_raw_string_literal(bytes: &mut [u8], start_idx: usize) -> usize {
    //find the delimiter
    let mut delim = vec![];
    let mut idx = start_idx;

    while idx < bytes.len() {
        let c = bytes[idx];
        idx += 1;
        if c == b'(' {
            break;
        }
        delim.push(c);
    }
    delim.push(b')');
    delim.push(b'\"');

    //now keep going and find the first position where the delimiter starts
    while idx < bytes.len() - delim.len() + 1 {
        if lookahead_delim(bytes, &delim, idx) {
            idx += delim.len();
            break;
        } else if !is_newline(bytes[idx]) {
            bytes[idx] = b'X';
        }
        idx += 1;
    }

    idx
}

fn clean_cpp_file_content(config: &Config, file_content: &mut String, ignore_safe: bool) {
    assert!(!file_content.is_empty());

    //remove all lines containing a safe tag
    if !ignore_safe {
        if let Cow::Owned(modified) = config.safe_tag_regex.replace_all(&file_content, "\n") {
            *file_content = modified;
        }
    }

    enum State {
        Code,
        SkipLine,
        Preprocessor,
        String,
        Char,
        MultiLine,
    }

    let mut state = State::Code;
    unsafe {
        // because as_mut_vec ignores UTF8, lol
        let bytes = file_content.as_bytes_mut();
        let mut i = 0;
        while i < bytes.len() - 1 {
            let cur = bytes[i];
            let next = bytes[i + 1];

            state = match state {
                State::Code if config.remove_comments && cur == b'/' && next == b'/' => {
                    State::SkipLine
                }
                State::Code if config.remove_strings && cur == b'"' => State::String,
                State::Code if config.remove_strings && cur == b'\'' => State::Char,
                State::Code if config.remove_comments && cur == b'/' && next == b'*' => {
                    State::MultiLine
                }
                State::Code if cur == b'#' => State::Preprocessor,
                State::Code if cur == b'R' && next == b'"' => {
                    i = remove_raw_string_literal(bytes, i + 2);
                    State::Code
                }

                //Preprocessor state: remain in the state until \n is found
                State::Preprocessor if is_newline(next) => State::Code,
                State::Preprocessor => State::Preprocessor,

                //unknown character: remain in Code state
                State::Code => State::Code,

                //after this line, all iterations on one of these states cause X to be written in replacement
                State::SkipLine if is_newline(next) => State::Code,
                State::String if is_newline(cur) => State::String,
                State::String if cur == b'\\' => {
                    //escape char, skip next
                    bytes[i] = b'X';
                    i += 1;
                    State::String
                }
                State::String if cur == b'"' => State::Code,

                State::Char if cur == b'\\' => {
                    //escape char, skip next
                    bytes[i] = b'X';
                    i += 1;
                    State::Char
                }
                State::Char if cur == b'\'' => State::Code,

                State::MultiLine if cur == b'*' && next == b'/' => State::Code,
                State::MultiLine if is_newline(cur) => State::MultiLine,
                _ => {
                    bytes[i] = b'X';
                    state
                }
            };
            i += 1;
        }
    }
}

async fn output_preprocessed(path: &Path, file_content: &str) {
    // debug option: print out whatever this file looks like after cleaning
    // let out_path = append_to_extension(path.to_owned(), ".preproc");
    let out_path = path;
    let mut outfile = File::create(out_path).await.unwrap();
    outfile.write_all(file_content.as_bytes()).await.unwrap();
}

#[allow(clippy::cognitive_complexity)]
async fn examine(
    config: &Config,
    path: &Path,
    replace_original_with_preprocessed: bool,
    ignore_safe: bool,
    sanity_checks: bool,
) -> Warnings {
    let mut warnings = Warnings::default();

    let mut file_content = String::new();

    let mut in_class = false;
    let in_header = path.ends_with(".h");
    let mut line_number = 0;

    let mut file = File::open(&path).await.unwrap_or_else(|e| {
        log::error!("{}: {}", path.display(), e);
        process::exit(1);
    });

    log::debug!("Checking {}", path.display());

    let result = file.read_to_string(&mut file_content).await;

    if result.is_err() {
        warnings.add(
            "This file contains invalid UTF8",
            &Info {
                path: path.to_path_buf(),
                line: None,
                snippet: None,
            },
        );
        return warnings;
    }

    if file_content.len() <= 1 {
        return warnings;
    }

    let original_lines = if sanity_checks {
        file_content.lines().count()
    } else {
        0
    };

    // TODO ensure stuff is ASCII manually
    clean_cpp_file_content(config, &mut file_content, ignore_safe);

    if sanity_checks && original_lines != file_content.lines().count() {
        output_preprocessed(path, &file_content).await;
        log::error!("Error: lines were lost during preprocessing");
        log::error!("File: {}", path.display());
    }

    if replace_original_with_preprocessed {
        output_preprocessed(path, &file_content).await;
    }

    let mut test_batch = vec![];

    //select all tests that should run on this file
    for test in &config.tests {
        if test.runs_on_path(&path) {
            test_batch.push(test);
        }
    }

    let mut fail_counts = vec![0; test_batch.len()];

    for line in file_content.lines() {
        line_number += 1;

        if !in_class && config.class_regex.is_match(line) {
            in_class = true; //TODO actually *exit* classes too...
        }

        // TODO //add a tab at the start to make pre-whitespaces coherent
        let info = Info {
            path: path.to_path_buf(),
            line: Some(line_number),
            snippet: Some(line),
        };

        for i in 0..test_batch.len() {
            let test = &test_batch[i];
            if test.run(line, in_header, in_class) {
                fail_counts[i] += 1;

                //failure mode #1: we went over the exact count required
                if fail_counts[i] > test.expected_fails.exactly {
                    warnings.add(&test.error, &info);
                }
            }
        }
    }

    //failure mode #2: there were not enough failures. Ha!
    for i in 0..test_batch.len() {
        let test = &test_batch[i];
        if fail_counts[i] < test.expected_fails.exactly {
            let info = Info {
                path: path.to_path_buf(),
                line: None,
                snippet: None,
            };

            warnings.add(&test.error, &info);
        }
    }

    // if any warning were emitted, see if a blame file is present
    // in which case, attach the blame information to the warnings
    if warnings.len() > 0 {
        let blame_path = path.to_str().unwrap().to_owned() + ".blame";
        if let Ok(mut file) = File::open(blame_path).await {
            file_content.clear();
            file.read_to_string(&mut file_content).await.unwrap();

            let lines: Vec<&str> = file_content.split('\n').collect();

            for list in warnings.map.values_mut() {
                for w in list {
                    if let Some(line) = w.line {
                        w.blame = Some(lines[line].to_owned());
                    }
                }
            }
        }
    }

    warnings
}

async fn run<W>(
    config: Config,
    output: &mut W,
    replace_original_with_preprocessed: bool,
    ignore_safe: bool,
    json_log_path: Option<&Path>,
) -> usize
where
    W: std::io::Write + Unpin,
{
    let mut paths: Vec<PathBuf> = vec![];

    for root in &config.roots {
        for entry in WalkDir::new(root) {
            if let Ok(entry) = entry {
                if entry.file_type().is_file() {
                    paths.push(entry.into_path());
                }
            } else {
                log::error!("Cannot find a folder in the root list: {}", root);
                process::exit(1);
            }
        }
    }

    let sanity_checks = false;

    let mut results = vec![];

    for path in paths {
        if config.should_check(&path) {
            let config = config.clone();

            let result = async_std::task::spawn(async move {
                examine(
                    &config,
                    &path,
                    replace_original_with_preprocessed,
                    ignore_safe,
                    sanity_checks,
                )
                .await
            });

            results.push(result);
        }
    }

    let mut warnings = Warnings::default();

    // accumulate all warnings in the same map
    for result in future::join_all(results.into_iter()).await {
        warnings.add_map(result);
    }

    let count = warnings.map.iter().fold(0, |c, (_, v)| c + v.len());
    
    if let Some(json_path) = json_log_path {
        let json_output = warnings.to_json();
        match SyncFile::create(json_path) {
            Ok(mut json_file) => {
                use std::io::Write;
                writeln!(json_file, "{}", json_output).unwrap();
                log::info!("JSON output written to {}", json_path.display());
            }
            Err(e) => {
                log::error!("Cannot create JSON output file {}: {}", json_path.display(), e);
            }
        }
    }
    
    write!(output, "{}", warnings).unwrap();
    if count == 1 {
        writeln!(output, "Found 1 issue!").unwrap();
    } else {
        writeln!(output, "Found {} issues!", count).unwrap();
    }
    count
}

fn open_output(maybe_path: Option<&str>) -> Box<dyn std::io::Write> {
    if let Some(path) = maybe_path {
        if let Ok(file) = SyncFile::create(path) {
            return Box::new(file);
        }
        log::warn!("Cannot open file at {}, defaulting to stdout", path);
    }

    Box::new(log_output::LogOutput)
}

async fn async_main() {
    const VERSION: &str = env!("CARGO_PKG_VERSION");

    let matches = App::new("A cpp linter")
        .version(VERSION)
        .about("Still pretty incomplete")
        .arg(Arg::with_name("JSON_PATH")
            .help("A JSON file containing the lints to apply to the program and the folders to \
                   scan")
            .value_name("Config File Path")
            .takes_value(true)
            .required(true))
        .arg(Arg::with_name("root_path")
            .help("The folder where to look for the code. Omitting it will default to the Json \
                   file's folder")
            .value_name("Root path")
            .short("r")
            .long("root_path")
            .takes_value(true))
        .arg(Arg::with_name("output")
            .help("The path of the output file. Defaults to stdout if not provided.")
            .value_name("Output file")
            .short("o")
            .long("output")
            .takes_value(true))
        .arg(Arg::with_name("replace-original-with-preprocessed")
            .help("[dev option] Pass in this flag if you want to see what the intermediate files look like.")
            .long("replace-original-with-preprocessed"))
        .arg(Arg::with_name("ignore-safe")
            .help("Ignore /*safe*/ tags and show them anyway in the output")
            .long("ignore-safe"))
        .arg(Arg::with_name("vs-log")
            .help("Use Visual Studio log style to show individual clickable errors in the Visual Studio output")
            .long("vs-log"))
        .arg(Arg::with_name("json-log")
            .help("Output warnings as structured JSON to the specified file")
            .value_name("JSON output file")
            .long("json-log")
            .takes_value(true))
        .get_matches();

    let path = PathBuf::from(matches.value_of("JSON_PATH").unwrap());

    if !path.is_file() {
        log::error!("{} is not a file, or couldn't be found!", path.display());
        process::exit(1);
    }

    let rootpath = match matches.value_of("root_path") {
        Some(value) => PathBuf::from(value),
        None => to_absolute_path(&path)
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf(),
    };

    let replace_original_with_preprocessed =
        matches.is_present("replace-original-with-preprocessed");

    let ignore_safe = matches.is_present("ignore-safe");

    let vs_log = matches.is_present("vs-log");

    let json_log_path = matches.value_of("json-log").map(|p| {
        let path = Path::new(p);
        if path.is_absolute() {
            PathBuf::from(p)
        } else {
            std::env::current_dir().unwrap().join(path)
        }
    });

    //log format
    if vs_log {
        log::error!("testing:error:desc");
        use std::io::Write;
        use env_logger::{Builder, Env};
        fn init_logger() {
            let env = Env::new()
                .default_filter_or("info");
            Builder::from_env(env)
                .format(|buf, record| {
                    let style = buf.style();

                    writeln!(
                        buf,
                        "{}",
                        style.value(record.args())
                    )
                })
                .init();
        }
        init_logger();
    } else {
        let log_env = env_logger::Env::new().default_filter_or("info");
        env_logger::init_from_env(log_env);
    }
    //end log format

    log::info!("Running acpplinter {}", VERSION);

    let mut output = open_output(matches.value_of("output"));

    if let Ok(mut file) = SyncFile::open(path.as_path()) {
        assert!(env::set_current_dir(rootpath).is_ok());

        match serde_json::from_reader(&mut file) {
            Ok(desc) => {
                if run(
                    Config::from_desc(desc),
                    &mut output,
                    replace_original_with_preprocessed,
                    ignore_safe,
                    json_log_path.as_deref(),
                )
                .await
                    == 0
                {
                    process::exit(0);
                } else {
                    process::exit(1);
                }
            }
            Err(e) => {
                log::error!("Invalid JSON");
                log::error!("{:?}", e);
                process::exit(1);
            }
        }
    } else {
        log::error!("Cannot open config {}", path.display());
        process::exit(1);
    }
}

fn main() {
    async_std::task::block_on(async_main())
}
