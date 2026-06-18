Set objFSO = CreateObject("Scripting.FileSystemObject")
strPath = objFSO.GetParentFolderName(WScript.ScriptFullName)

Set objShell = CreateObject("Shell.Application")

' Use global pythonw.exe so it works on the evaluator's computer
objShell.ShellExecute "pythonw.exe", Chr(34) & strPath & "\main.py" & Chr(34), strPath, "runas", 0
