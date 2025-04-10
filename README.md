# 🧩 LLM Based Test Generator

## 📚 Project Overview

This project demonstrates the use of **symbolic execution** to analyze the paths of executables written in both **C** and **Python**. The project leverages the 🛠️ **Angr framework** and **Claripy** to inject symbolic variables into the binaries and explore all possible execution paths. Its main goals are to identify specific outputs and determine the symbolic inputs that lead to those outputs.

There are two versions of the code:
- **example.c:** A C program whose execution paths are explored using symbolic execution via the `symbolic_c.py` script.
- **example1.py:** A Python equivalent that also demonstrates branching logic. This Python script is converted to a binary using PyInstaller and analyzed symbolically via `symbolic_python.py`.

Additionally, the repository includes examples of branching logic in both languages and highlights the role of **large language models (LLMs)** in generating test cases for software systems.

---

## ✨ Features

- 🔍 **Symbolic Execution:** Analyze multiple execution paths using symbolic inputs injected into binaries.
- 🛠️ **Angr Framework:** Utilize Angr for advanced binary analysis.
- 🐍 **Language Diversity:** Contains both a C example (`example.c`) and a Python example (`example1.py`).
- 🤖 **LLM-Based Test Generation:** Explore how AI can assist in generating test cases.

---

## ⚙️ Prerequisites

### 🖥️ Software Requirements

- **Python 3.8+**
- **Angr:** Install via `pip install angr`
- **PyInstaller:** Install via `pip install pyinstaller` (required for converting Python scripts into binaries)
- **C Compiler:** (e.g., `gcc`) for compiling the C program
- A binary file for analysis generated from the respective source code

---

## 🚀 Installation and Execution

### 1. Install Dependencies

Install all Python dependencies by running:
```bash
pip install -r requirements.txt
```

### 2. Generate Binaries

#### For the C Program:
- **Compile the C source code (`example.c`):**
  ```bash
  gcc example.c -o example_c
  ```
- This command compiles `example.c` into the executable `example_c`.

#### For the Python Program:
- **Convert the Python script (`example1.py`) into a standalone binary:**
  ```bash
  pyinstaller --onefile example1.py
  ```
- The binary will be located in the `dist` directory (e.g., `dist/example1`).

### 3. Execute the Programs Normally

#### For the C Binary:
- **Run the C binary as usual:**
  ```bash
  ./example_c
  ```

#### For the Python Binary:
- **Run the Python binary (converted by PyInstaller):**
  ```bash
  ./dist/example1
  ```

### 4. Run Symbolic Execution

#### For the C Program:
- **Execute symbolic analysis using `symbolic_c.py`:**
  ```bash
  python symbolic_c.py
  ```

#### For the Python Program:
- **Execute symbolic analysis using `symbolic_python.py`:**
  ```bash
  python symbolic_python.py
  ```

The symbolic execution scripts explore the execution paths of the binaries and output:
- The selected path (e.g., "Path 1" or "Path 2").
- The symbolic inputs (e.g., variables such as `x` and `y`) that led to each path.
- The final output of the program.

---

## 🐍 Example Code

### C Example: `example.c`
The `example.c` program demonstrates simple branching logic based on input values. The symbolic execution tool (`symbolic_c.py`) examines the different possible execution paths.

#### To Run:
```bash
./example_c
```

#### Expected Output:
The program prompts for inputs and returns either `"Path 1"` or `"Path 2"` depending on the logic implemented.

### Python Example: `example1.py`
The `example1.py` script contains the same logic as the C version. After converting it into a binary with PyInstaller, it can be executed normally and analyzed symbolically using `symbolic_python.py`.

#### To Run:
```bash
./dist/example1
```

#### Expected Output:
Similarly, it prompts for inputs and displays either `"Path 1"` or `"Path 2"` based on the calculated values.

---

## 📂 File Structure

```plaintext
├── build/                         # Build directory for binary analysis
├── dist/                          # Directory containing binaries (e.g., `example1`)
├── .gitignore                     # Ignore unnecessary files
├── example.c                      # C example of branching logic
├── example1.py                    # Python example of branching logic
├── example_binary.spec            # Configuration file for example binary (if needed)
├── symbolic_c.py                  # Symbolic execution script for the C binary
├── symbolic_python.py             # Symbolic execution script for the Python binary
├── requirements.txt               # List of dependencies
```

---

## 📜 License

This project is licensed under the **IIT Kharagpur**.