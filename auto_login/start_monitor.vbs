Option Explicit

Dim shell, fso, scriptDir, pythonw, python, command, logFile, handle
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

scriptDir = "项目文件位置\auto login"
pythonw = "python环境位置\pythonw.exe"
python = "python环境位置\python.exe"
logFile = scriptDir & "\startup_launcher.log"

If fso.FileExists(pythonw) Then
  command = """" & pythonw & """ """ & scriptDir & "\monitor_login.py"""
ElseIf fso.FileExists(python) Then
  command = """" & python & """ """ & scriptDir & "\monitor_login.py"""
Else
  command = "python """ & scriptDir & "\monitor_login.py"""
End If

Set handle = fso.OpenTextFile(logFile, 8, True)
handle.WriteLine Now & " launching: " & command
handle.Close

shell.CurrentDirectory = scriptDir
shell.Run command, 0, False
