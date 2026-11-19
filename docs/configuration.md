# Configuration

Python Scanner reads an optional .python-scanner.toml file from the target directory.

~~~toml
[scanner]
max_files = 5000
max_file_size = 1000000
max_line_length = 100
exclude = [".git/**", ".venv/**", "build/**", "dist/**"]
~~~

| Setting | Default | Description |
|---|---:|---|
| max_files | 5000 | Maximum number of Python files discovered in a directory |
| max_file_size | 1000000 | Maximum source-file size in bytes |
| max_line_length | 100 | Threshold used by the line-length rule |
| exclude | built-in list | Glob patterns matched against project-relative paths |

CLI options --max-files, --max-file-size, and --max-line-length override configuration values. Invalid non-positive values are rejected.
