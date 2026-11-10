# 🔍 Python Scanner

A code analysis and security inspection tool for Python projects.

---

## About the Project

Python Scanner is a tool for inspecting and analyzing Python files and projects.

The application is developed with Python and Kivy and aims to bring several practical code-inspection capabilities together in one environment.

The project's main focus is finding potential code issues, examining statement structure, detecting sensitive information, and inspecting project dependencies.

An important design principle is the use of **Static Analysis**: source code is read and analyzed without executing the program being inspected.

---

## ⚙️ How It Works

The inspection process starts when a file or folder is selected. After the input is prepared, different analysis components process it.

### 01 — Selecting Files or Folders

Users can select a single Python file or an entire project folder.

On Android, file and folder selection uses the Android Storage Access Framework (SAF).

This opens Android's native file picker, allowing users to navigate to the desired location through the file manager.

When a folder is selected, the application looks for relevant project files, including:

- `.py` files
- `requirements.txt`
- `pyproject.toml`

Limits on file count, folder depth, and data size help prevent excessive processing.

Selected files are read through Android's storage access mechanism and prepared in the application's internal workspace.

### 02 — Preparing and Reading Source Code

After files are collected, their contents are read and prepared for analysis.

The application identifies files that can be inspected and extracts the information required by the different analysis components.

Source files are not executed or imported during this process; their contents are treated as analysis input.

### 03 — Code Structure Analysis (AST)

One of the application's main components is built around Python's standard `ast` module.

AST, or Abstract Syntax Tree, represents the syntactic structure of code as a processable tree.

This allows the application to inspect structures such as:

- Function and class definitions
- Conditions and loops
- Import statements
- Function calls
- Different statement structures

Compared with simple text searching, this approach provides more structural information to the analyzer.

It can also detect parsing errors in files with syntax problems, such as an unclosed parenthesis or an invalid statement structure.

### 04 — Security Inspection

The security component is designed to find possible signs of sensitive information and suspicious patterns.

It uses Regular Expressions, text patterns, and entropy analysis.

Items inspected include:

- API keys
- Access tokens
- Possible passwords
- Secret strings
- Suspicious values in source code

#### Entropy Analysis

Sometimes sensitive information is stored in strings that do not follow a recognizable pattern.

In such cases, entropy can help identify strings with a high diversity of characters.

High entropy alone does not mean that a string contains confidential information; it is only one signal used to identify suspicious values.

#### Secret Masking

To avoid displaying the full value of detected sensitive information in reports, the application can mask the main part of a detected value.

### 05 — Dependency Inspection

Another part of the analysis focuses on project dependencies.

The application reads common package-management files and extracts information about the libraries used by the project.

Supported formats:

- `requirements.txt`
- `pyproject.toml`

For example, the expression `scikit-learn>=1.4` is processed so the package name can be separated from its version constraint.

This feature helps identify a project's dependency structure; it does not independently verify library security or whether packages are up to date.

### 06 — Additional Analysis Tools

Alongside the built-in analyzer, the application can optionally use two well-known Python tools.

| Tool | Purpose |
|---|---|
| Ruff | Checks code issues and certain style violations |
| Bandit | Detects some potentially suspicious security patterns |

These tools are optional. The main built-in analysis components remain available if they are not installed.

### 07 — Background Processing

Analyzing large projects can take time. For this reason, the main analysis operations run in a separate thread.

The application uses:

- `Threading` for background operations
- `Queue` to transfer information between processing and the user interface
- `BackgroundTask` to manage analysis tasks

This structure helps keep the user interface responsive while files are being inspected.

### 08 — Final Report

After inspection is complete, the analysis results are prepared for display in the user interface.

The report can include:

- Inspected files
- Syntax analysis status
- Detected issues
- Potential security findings
- Masked sensitive information
- Extracted dependencies
- Results from additional tools

Reports can also be saved in JSON format so analysis data can be used outside the application.

---

## 🧩 Technologies Used

| Technology | Role in the Project |
|---|---|
| Python | Main development language |
| Kivy | Graphical user interface |
| AST | Code structure analysis |
| Regex | Text-pattern detection |
| Entropy | Inspection of suspicious strings |
| Threading | Background processing |
| Queue | Processing data transfer |
| JSON | Report storage |
| Android SAF | File and folder selection |
| Ruff | Additional code analysis |
| Bandit | Additional security inspection |

---

## 📱 User Interface and Runtime Environment

The graphical interface is developed with Kivy.

One of the project's goals is to make the tool usable on Android phones. Users can select a file or folder, start an analysis, and view the results inside the application.

The project is currently designed around a single main Python file, with input handling, analysis, and result presentation contained in the same application.

---

## Notes on Analysis Accuracy

Python Scanner is a static-analysis tool and is not intended to detect every possible software issue.

- Some findings may be false positives.
- Not all runtime problems can be detected through static analysis.
- Detecting a suspicious string does not necessarily mean a vulnerability exists.
- Extracting dependency names is not the same as checking library security.
- Results from external tools depend on their installation and availability.

For these reasons, results should be treated as supporting information for further review.

---

## 🎯 Project Goal

The goal of Python Scanner is to build a practical tool for inspecting Python code—one that combines several analysis methods and can also be used in a mobile environment.

The project focuses on structural analysis, security inspection, and making the process of reviewing Python files easier.

---

**Python Scanner**

Code inspection · Static analysis · Security checks