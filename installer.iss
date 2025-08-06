[Setup]
AppName=@Chat
AppVersion=0.1.0
DefaultDirName={userdesktop}\@Chat
DefaultGroupName=@Chat
OutputBaseFilename=@Chat Installer
Compression=lzma
SolidCompression=yes

[Files]
Source: "build\exe.win-amd64-3.13\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\@Chat"; Filename: "{app}\@Chat.exe"
Name: "{group}\Uninstall @Chat"; Filename: "{uninstallexe}"
