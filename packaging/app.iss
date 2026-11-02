#ifndef AppVersion
  #error AppVersion must be supplied by the build entry
#endif
#ifndef SourceDir
  #error SourceDir must be supplied by the build entry
#endif
#ifndef OutputDir
  #error OutputDir must be supplied by the build entry
#endif
[Setup]
AppId=ClaudeLaunchCenter
AppName=Claude 检测助手
AppVersion={#AppVersion}
DefaultDirName={localappdata}\Programs\ClaudeLaunchCenter
PrivilegesRequired=lowest
CloseApplications=no
RestartApplications=no
Uninstallable=not PortableCheck
OutputDir={#OutputDir}
OutputBaseFilename=ClaudeLaunchCenterSetup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
UninstallDisplayIcon={app}\ClaudeLaunchCenter.exe
[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
[Icons]
Name: "{userprograms}\Claude 检测助手"; Filename: "{app}\ClaudeLaunchCenter.exe"; Check: not PortableCheck
Name: "{userdesktop}\Claude 检测助手"; Filename: "{app}\ClaudeLaunchCenter.exe"; Check: not PortableCheck

[Code]
function PortableCheck: Boolean;
begin
  Result := ExpandConstant('{param:portable|0}') = '1';
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Locator, Services, Processes: Variant;
begin
  Result := '';
  try
    Locator := CreateOleObject('WbemScripting.SWbemLocator');
    Services := Locator.ConnectServer('.', 'root\CIMV2');
    Processes := Services.ExecQuery('SELECT ProcessId FROM Win32_Process WHERE Name = ''ClaudeLaunchCenter.exe''');
    if Processes.Count <> 0 then
      Result := '检测助手仍在运行。请先保存需要保留的输入，再正常关闭检测助手窗口，随后重试。安装器不会强制结束进程。';
  except
    Result := '无法确认检测助手已退出，已停止更新。请确认正常关闭后重试。';
  end;
end;
