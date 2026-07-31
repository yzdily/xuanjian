; ============================================================
; installer.iss — Inno Setup 安装脚本 for 玄鉴 XuanJian
; 用法: 用 Inno Setup Compiler (iscc.exe) 编译本脚本
;   iscc scripts\installer.iss
; ============================================================

#define MyAppName      "玄鉴 XuanJian"
#define MyAppVersion   "0.1.0"
#define MyAppPublisher "XuanJian Team"
#define MyAppExeName   "XuanJian.exe"
#define MyAppURL       "https://github.com/xuanjian/xuanjian"

[Setup]
AppId={{8F2B4A1E-6C3D-4E5F-9A7B-1C2D3E4F5A6B}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\XuanJian
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE
InfoBeforeFile=..\README.md
OutputDir=..\dist
OutputBaseFilename=XuanJian-Setup-v{#MyAppVersion}
SetupIconFile=
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequiredOverridesAllowed=dialog
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
VersionInfoVersion={#MyAppVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=GapHunter AI 安全测试工具
VersionInfoTextVersion={#MyAppVersion}

[Languages]
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; 主程序（单文件模式，包含所有资源）
Source: "..\dist\XuanJian.exe"; DestDir: "{app}"; Flags: ignoreversion
; 若未来使用 onedir 模式，可取消下面注释
; Source: "..\dist\XuanJian\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs

[Dirs]
; 创建可写的数据目录（权限兼容普通用户/管理员）
Name: "{app}\data"; Permissions: users-modify
Name: "{app}\data\logs"; Permissions: users-modify
Name: "{app}\data\notes"; Permissions: users-modify
Name: "{app}\data\reports"; Permissions: users-modify
Name: "{app}\data\tasks"; Permissions: users-modify

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; 安装完成后可选启动
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
; WebView2 运行时静默安装（若系统缺失）
Filename: "{tmp}\MicrosoftEdgeWebview2Setup.exe"; Parameters: "/silent /install"; Flags: skipifdoesntexist; StatusMsg: "正在检查/安装 WebView2 运行时..."

[UninstallDelete]
Type: filesandordirs; Name: "{app}\data"
Type: filesandordirs; Name: "{app}\ms-playwright"
Type: filesandordirs; Name: "{app}\skills_my"

[Code]
// ------------------------------------------------------------
// WebView2 运行时检测与自动下载
// ------------------------------------------------------------
function IsWebView2Installed(): Boolean;
begin
  // 检查 64 位注册表项
  Result := RegKeyExists(HKLM, 'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}');
  if not Result then
    // 再检查 32 位注册表项
    Result := RegKeyExists(HKLM, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}');
end;

function InitializeSetup(): Boolean;
var
  WebView2Installer: String;
begin
  Result := True;

  if not IsWebView2Installed() then
  begin
    Log('WebView2 Runtime not found. Downloading...');
    WebView2Installer := ExpandConstant('{tmp}\MicrosoftEdgeWebview2Setup.exe');

    try
      DownloadTemporaryFile(
        'https://go.microsoft.com/fwlink/p/?LinkId=2124703',
        WebView2Installer,
        '',
        @OnDownloadProgress
      );
      Log('WebView2 installer downloaded to ' + WebView2Installer);
    except
      MsgBox(
        '自动下载 WebView2 运行时失败。' + #13#10 +
        '程序部分功能（如内置浏览器）可能无法正常使用。' + #13#10 +
        '请手动下载安装：https://developer.microsoft.com/zh-cn/microsoft-edge/webview2/',
        mbError, MB_OK
      );
      // 允许继续安装，不影响主程序
    end;
  end
  else
  begin
    Log('WebView2 Runtime is already installed.');
  end;
end;

// ------------------------------------------------------------
// 下载进度回调（必须存在，即使为空实现）
// ------------------------------------------------------------
function OnDownloadProgress(const Url, FileName: String; const Progress, ProgressMax: Int64): Boolean;
begin
  if ProgressMax <> 0 then
    Log(Format('Downloading %s: %d / %d', [FileName, Progress, ProgressMax]));
  Result := True;
end;
