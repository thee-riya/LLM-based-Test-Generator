# 🧩 LLM Based Test Generator

## 📚 Project Overview

This project demonstrates the use of **symbolic execution** to analyze the paths of a binary executable. Using the 🛠️ **Angr framework** and **Claripy**, symbolic variables are injected into the binary to explore all possible execution paths. The project aims to identify specific outputs and evaluate the symbolic inputs that lead to those outputs.

Additionally, the repository includes a Python function with branching logic ("Path 1" and "Path 2") and highlights the role of **large language models (LLMs)** in generating test cases for software systems.

---

## ✨ Features

- 🔍 **Symbolic Execution:** Analyze execution paths using symbolic inputs to binaries.
- 🛠️ **Angr Framework:** Leverage Angr for advanced binary analysis.
- 🐍 **Python Examples:** Demonstrates branching logic and decision-making.
- 🤖 **LLM-Based Test Generation:** Explore using AI for test-case generation.

---

## ⚙️ Prerequisites

### 🖥️ Software Requirements

- Python 3.8+
- Angr (`pip install angr`)
- PyInstaller (`pip install pyinstaller`)
- A binary file for analysis (generated from `example_binary.py`)

---

## 🚀 Installation and Execution

Follow these steps to execute the project:

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Generate the binary:**
   - Convert the Python script `example_binary.py` into a standalone binary:
     ```bash
     pyinstaller --onefile example_binary.py
     ```
   - This will generate a binary file in the `dist` directory.

3. **Test the binary:**
   - To check if the binary is working correctly:
     ```bash
     ./dist/example_binary
     ```

4. **Run symbolic execution:**
   - Use the `symbolic_execution.py` script to analyze the binary:
     ```bash
     python symbolic_execution.py
     ```

---

## 🛠️ Symbolic Execution

The `symbolic_execution.py` script explores execution paths of the binary file (`example_binary`) and outputs:

- The path taken (e.g., "Path 1" or "Path 2").
- The symbolic inputs (`x` and `y`) that lead to the result.
- The program's final output.

---

## 🐍 Example Function

The `example_binary.py` script demonstrates simple branching logic. It contains a function that determines whether the result falls into "Path 1" or "Path 2" based on the sum of two inputs.

#### 📜 To Run:
```bash
python example_binary.py
```

#### 🎯 Expected Output:
The script prompts for inputs `x` and `y` and returns either `"Path 1"` or `"Path 2"` based on the logic in the `example_function`.

---

## 📂 File Structure

```plaintext
├── build/                        # Build directory for binary analysis
├── dist/                         # Directory containing binaries (e.g., `example_binary`)
├── .gitignore                    # Ignore unnecessary files
├── example_binary.py             # Python example of branching logic
├── example_binary.spec           # Configuration file for example binary
├── ex_binary_simplified.py       # Example binary analysis with Angr
├── ex_binary_simplified.spec     # Configuration file for binary analysis
├── symbolic_execution.py         # Symbolic execution script using Angr
├── requirements.txt              # List of dependencies
```
---

## 📜 License

This project is licensed under the **IIT Kharagpur**.

