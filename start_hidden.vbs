Set objFSO = CreateObject("Scripting.FileSystemObject")
strPath = objFSO.GetParentFolderName(WScript.ScriptFullName)

Set objShell = CreateObject("Shell.Application")

' Use the pythonw.exe from the newly created virtual environment
objShell.ShellExecute Chr(34) & strPath & "\.venv\Scripts\pythonw.exe" & Chr(34), Chr(34) & strPath & "\main.py" & Chr(34), strPath, "runas", 0
