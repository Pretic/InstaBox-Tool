"""Pseudo-terminal credential + menu checks. No real credentials or endpoints."""
import json, os, pty, select, shutil, signal, stat, subprocess, tempfile, time, re, shlex, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
TMP=Path(tempfile.mkdtemp(prefix='ibt-terminal-')); HOME=TMP/'home'; BIN=TMP/'bin'
CLI=HOME/'.local/share/insta-box/cli'
MODULE=HOME/'.local/share/insta-box/management/node_modules/@insforge/instabox-sdk'
DUMMY='ibk_FAKE_FOR_CHECKS_ONLY'
MENU_TRANSCRIPTS=[]
def mock(name,source):
 p=BIN/name;p.write_text('#!/usr/bin/env bash\n'+source);p.chmod(0o755)
def plain_text(value):
 return re.sub(r'\x1b\[[0-9;]*[A-Za-z]','',value)
def execute(script,args=(),responses=(), extra=None):
 pid,fd=pty.fork()
 if pid==0:
  env=dict(os.environ,HOME=str(HOME),PATH=str(BIN)+':'+os.environ['PATH'],TERM='xterm',IBT_NO_CLEAR='1',NO_COLOR='')
  env.pop('TZ',None)
  env.update(extra or {})
  os.execvpe('bash',['bash',str(ROOT/script),*args],env)
 out=b''; queue=list(responses);code=None;consumed=0
 try:
  deadline=time.monotonic()+10
  while time.monotonic()<deadline:
   ready,_,_=select.select([fd],[],[],0.1)
   if ready:
    try: c=os.read(fd,8192)
    except OSError: break
    if not c: break
    out+=c
    text=out.decode(errors='replace')
    if queue and queue[0][0] in text[consumed:]:
     needle,reply=queue.pop(0)
     consumed=text.index(needle,consumed)+len(needle)
     os.write(fd,reply.encode()+b'\n')
   # Child exit can precede reading the final PTY chunk. Keep draining until
   # EOF/EIO so a successful command's last status line is not lost.
   if code is None:
    done,status=os.waitpid(pid,os.WNOHANG)
    if done: code=os.waitstatus_to_exitcode(status)
  if code is None:
   done,status=os.waitpid(pid,os.WNOHANG)
   if not done:
    time.sleep(.1);done,status=os.waitpid(pid,os.WNOHANG)
   if done: code=os.waitstatus_to_exitcode(status)
   else:
    os.kill(pid,signal.SIGKILL);os.waitpid(pid,0);raise AssertionError('Unexpected prompt or hang: '+out.decode(errors='replace'))
 finally: os.close(fd)
 transcript=out.decode(errors='replace')
 if Path(script).name=='ibt.sh': MENU_TRANSCRIPTS.append(transcript)
 return code,transcript
try:
 CLI.mkdir(parents=True);MODULE.mkdir(parents=True);BIN.mkdir()
 for f in ['ibt.sh','install.sh','platform.mjs','keepalive.sh','heartbeat.py','cloud.py','ssh_tokens.py','machine_opt.py','node_probe.py','system_info.py','ui_time.py','cf_select.py']:shutil.copy2(ROOT/f,CLI/f)
 (MODULE/'package.json').write_text('{}')
 mock('node','[[ ${NODE_MUST_NOT_RUN:-0} != 1 ]] || exit 91\nif [[ "$1" == "-p" ]]; then echo 22; elif [[ "$1" == "-" ]]; then echo "尚未检查"; else echo "AUTH_OK"; fi\n')
 mock('systemctl','''case "${2:-}" in
 is-enabled) echo enabled ;;
 list-timers) printf '[{"unit":"insta-box-heartbeat.timer","activates":"insta-box-heartbeat.service","next":%s,"last":null}]\\n' "$(( ($(date +%s) + 120) * 1000000 ))" ;;
 show) printf '%s\\n' 'Id=insta-box-heartbeat.service' 'LoadState=loaded' 'ActiveState=inactive' 'SubState=dead' ;;
 *) printf '%s\\n' "${MOCK_SERVICE_STATE:-active}" ;;
esac
''')
 mock('loginctl','echo yes\n')
 mock('ssh',"printf '%s\\n' IB_HEARTBEAT_OK\n")
 mock('hostname','echo instabox-example\n')
 mock('curl','printf "%s\\n" "$*" >> "$HOME/unexpected-network"\nexit 97\n')
 mock('journalctl','printf "%s\\n" "$*" >> "$HOME/journal-actions"\nprintf "JOURNAL_ACTION:%s\\n" "$*"\n')
 # Exercise shell menu routing without contacting the real cloud. The Python
 # overview/selection implementations are covered by test_cloud.py.
 mock('python3','if [[ "$1" == */cloud.py && ${2:-} != key ]]; then\n'
      '  printf "%s\\n" "${*:2}" >> "$HOME/cloud-actions"\n'
      '  if [[ ${MOCK_CLOUD_FAIL:-0} == 1 ]]; then echo "无法读取机器列表"; exit 1; fi\n'
      '  if [[ ${2:-overview} == overview ]]; then\n'
      '    printf "%s\\n" "共 5 台 · 运行 1 台 · 暂停 4 台" "编号  机器  状态  本机保活" '
      '"1  insta  运行中  保活正常" "2  instwo  已暂停  待启动" '
      '"3  insthree  已暂停  未配置" "4  insfour  已暂停  未配置" '
      '"5  insfive  已暂停  未配置"\n'
      '  else printf "已调用：%s\\n" "${*:2}"; fi\n'
      'elif [[ "$1" == */machine_opt.py ]]; then\n'
      '  printf "%s\\n" "${*:2}" >> "$HOME/optimization-actions"\n'
      '  if [[ ${2:-} == status ]]; then printf "%s\\n" "物理内存： 8 GiB" "交换空间： 未启用";\n'
      '  else printf "OPT_ACTION:%s\\n" "${*:2}"; fi\n'
      'elif [[ "$1" == */system_info.py ]]; then\n'
      '  printf "%s\\n" "${*:2}" >> "$HOME/info-actions"\n'
      '  printf "INFO_TZ:%s\\n" "${TZ:-system}"\n'
      '  printf "%s\\n" "本机名称： fixture" "物理内存： 8 GiB"\n'
      'elif [[ "$1" == */cf_select.py ]]; then\n'
      '  printf "%s\\n" "${*:2}" >> "$HOME/cf-actions"\n'
      '  printf "CF_ACTION:%s\\n" "${*:2}"\n'
      'else exec '+shlex.quote(sys.executable)+' "$@"; fi\n')
 code,first=execute('keepalive.sh',['check'],[('输入 InstaBox API Key',DUMMY),('保存授权','y')])
 assert code==0,first
 key=HOME/'.config/insta-box/api-key'
 assert key.read_text().strip()==DUMMY
 assert stat.S_IMODE(key.stat().st_mode)==0o600
 assert stat.S_IMODE(key.parent.stat().st_mode)==0o700
 assert DUMMY not in first
 code,second=execute('keepalive.sh',['check'])
 assert code==0 and '输入 InstaBox' not in second,second
 code,menu=execute('ibt.sh',[],[('请选择','0')])
 assert code==0,menu
 plain=plain_text(menu)
 menu_lines=[line for line in plain.splitlines() if re.match(r'\s*\d+\.\s',line)]
 assert len(menu_lines)==8,plain
 assert all(len(re.findall(r'\d+\.\s',line))==1 for line in menu_lines)
 main_options=[('1','本机信息'),('2','查看节点'),('3','节点管理'),('4','机器保活'),('5','机器管理'),('6','机器优化'),('7','更新卸载'),('0','退出菜单')]
 assert re.findall(r'^\s*(\d+)\.\s+([^\r\n]+)',plain,re.M)==main_options,plain
 status_rows=[line for line in plain.splitlines() if re.match(r'\s*(本机名称|保活状态|节点状态)：',line)]
 assert [re.match(r'^  ([^：]+)： \S',line).group(1) for line in status_rows]==['本机名称','保活状态','节点状态'],status_rows
 assert '测试' not in plain
 assert '\x1b[38;5;75m' in menu and '\x1b[32m' in menu,menu
 assert 'InstaBox Tool' in plain and '作者 Pre' in plain and 'Insta-Sing-box' not in plain,plain
 assert '互保' not in plain and 'v0.0.1' in plain,plain
 code,mono=execute('ibt.sh',[],[('请选择','0')],{'NO_COLOR':'1'})
 assert code==0 and '\x1b[' not in mono,mono
 code,failed=execute('ibt.sh',[],[('请选择','0')],{'MOCK_SERVICE_STATE':'failed'})
 assert code==0 and '\x1b[31m异常' in failed,failed
 responses=[('请选择','5')]
 for choice in ['2','3','4','1','6']:
  responses.extend([('刷新机器列表',choice),('按回车返回','')])
 # The protection submenu can be cancelled without an API action, then used
 # for both explicit switches through the existing shared selection workflow.
 responses.extend([('刷新机器列表','5'),('返回上级菜单','0'),
  ('刷新机器列表','5'),('返回上级菜单','1'),('按回车返回',''),
  ('返回上级菜单','2'),('按回车返回',''),('返回上级菜单','0')])
 responses.extend([('刷新机器列表','9'),('刷新机器列表','0'),('请选择','0')])
 code,cloud=execute('ibt.sh',[],responses)
 assert code==0 and '暂停所选机器' in cloud and '管理账户授权' in cloud and '云端机器管理' not in cloud,cloud
 assert all(name in cloud for name in ['insta','instwo','insthree','insfour','insfive']),cloud
 calls=(HOME/'cloud-actions').read_text().splitlines()
 assert [call for call in calls if call!='overview']==[
  'batch start','batch pause','batch stop','info --choose','operations','protect on','protect off'],calls
 assert calls.count('overview')==9,calls
 code,overview=execute('ibt.sh',['cloud'])
 assert code==0 and '共 5 台' in overview and '本机保活' in overview,overview
 code,unavailable=execute('ibt.sh',[],[('请选择','5'),('刷新机器列表','7'),
  ('清除本机授权','0'),('刷新机器列表','0'),('请选择','0')],{'MOCK_CLOUD_FAIL':'1'})
 assert code==0 and '列表暂时无法读取' in unavailable and '更新访问密钥' in unavailable,unavailable
 code,tokens=execute('ibt.sh',[],[('请选择','4'),('查看保活详情','4'),('配置自动换新','0'),('查看保活详情','0'),('请选择','0')])
 assert code==0 and '手动更新凭据' in tokens and '查看换新状态' in tokens,tokens
 assert all(label in tokens for label in ('管理保活目标','管理自动任务','打开机器管理')),tokens

 # Route the real menu from an isolated installed CLI copy. Its adjacent core
 # stub records commands, so navigation cannot download or change host services.
 core_calls=HOME/'core-actions'
 (CLI/'install.sh').write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$HOME/core-actions"\nprintf "CORE_ACTION:%s\\n" "$*"\n'
  'if [[ "$1" == repair && ${MOCK_REPAIR_FAIL:-0} == 1 ]]; then exit 1; fi\n')
 # Opening/refreshing local information is read-only. Timezone changes stay in
 # the isolated user configuration and must take effect in this same menu.
 info_calls=HOME/'info-actions'
 code,info_read=execute(CLI/'ibt.sh',[],[
  ('请选择','1'),('刷新本机信息','1'),('刷新本机信息','0'),('请选择','0')])
 assert code==0 and info_calls.read_text().splitlines()==['',''],info_read
 assert not (HOME/'.config/insta-box/display-timezone').exists(),info_read
 code,tz_menu=execute(CLI/'ibt.sh',[],[
  ('请选择','1'),('设置显示时区','2'),('设置其他时区','2'),('按回车返回',''),
  ('设置其他时区','0'),('设置显示时区','2'),('设置其他时区','1'),('按回车返回',''),
  ('设置其他时区','3'),('输入 IANA 时区','Asia/Tokyo'),('按回车返回',''),
  ('设置其他时区','0'),('设置显示时区','0'),('请选择','0')])
 assert code==0 and 'INFO_TZ:Asia/Shanghai' in tz_menu and 'INFO_TZ:Asia/Tokyo' in tz_menu,tz_menu
 assert '生效来源： 工具设置' in tz_menu and '环境指定' not in tz_menu,tz_menu
 tz_file=HOME/'.config/insta-box/display-timezone'
 assert tz_file.read_text().strip()=='Asia/Tokyo' and stat.S_IMODE(tz_file.stat().st_mode)==0o600
 code,persisted=execute(CLI/'ibt.sh',['info','--json'])
 assert code==0 and 'INFO_TZ:Asia/Tokyo' in persisted and info_calls.read_text().splitlines()[-1]=='--json',persisted
 code,override=execute(CLI/'ibt.sh',['info'],extra={'TZ':'America/New_York'})
 assert code==0 and 'INFO_TZ:America/New_York' in override,override
 code,reset=execute(CLI/'ibt.sh',['timezone','reset'])
 assert code==0 and not tz_file.exists(),reset
 code,system_time=execute(CLI/'ibt.sh',['info'])
 assert code==0 and 'INFO_TZ:system' in system_time,system_time
 node_state=CLI.parent/'state.conf'
 assert not node_state.exists()
 code,uninstalled=execute(CLI/'ibt.sh',[],[
  ('请选择','2'),('一键安装节点','0'),('请选择','3'),('一键安装节点','0'),('请选择','0')])
 assert code==0,uninstalled
 uninstalled_options=re.findall(r'^\s*(\d+)\.\s+([^\r\n]+)',plain_text(uninstalled),re.M)
 assert [item for item in uninstalled_options if item not in main_options]==[
  ('1','一键安装节点'),('0','返回上级菜单'),('1','一键安装节点'),('0','返回上级菜单')],uninstalled
 assert not core_calls.exists(),'Opening an uninstalled node must not install or call the core'
 node_state.write_text('mode=quick\nuuid=fixture-existing-node\n')
 node_state.chmod(0o600)
 saved_node=(node_state.read_bytes(),node_state.stat().st_ino)
 code,view=execute(CLI/'ibt.sh',[],[('请选择','2'),('按回车返回',''),('请选择','0')])
 assert code==0 and 'CORE_ACTION:show' in view,view
 assert core_calls.read_text().splitlines()==['show'],'Viewing a configured node must only show its links'
 assert (node_state.read_bytes(),node_state.stat().st_ino)==saved_node
 core_calls.write_text('')
 code,node_routes=execute(CLI/'ibt.sh',[],[
  ('请选择','3'),('修复现有节点','1'),('返回节点管理','0'),('按回车返回',''),
  ('管理域名隧道','3'),('关闭快捷隧道','1'),('按回车返回',''),
  ('设置快捷传输','7'),('按回车返回',''),
  ('设置快捷传输','8'),('使用备用传输','1'),('更换临时隧道传输并生成新地址','n'),('按回车返回',''),
  ('使用备用传输','2'),('更换临时隧道传输并生成新地址','y'),('按回车返回',''),
  ('使用备用传输','0'),('管理开机自启','9'),
  ('关闭开机重建','1'),('按回车返回',''),('关闭开机重建','2'),('按回车返回',''),
  ('关闭开机重建','0'),('设置快捷传输','0'),
  ('查看节点日志','6'),('查看固定日志','1'),('按回车返回',''),
  ('查看固定日志','2'),('按回车返回',''),('查看固定日志','3'),('按回车返回',''),
  ('查看固定日志','0'),('查看运行状态','4'),('按回车返回',''),
  ('重启节点服务','5'),('按回车返回',''),('检查节点连接','7'),('按回车返回',''),
  ('修复现有节点','0'),('请选择','0')])
 assert code==0,node_routes
 assert core_calls.read_text().splitlines()==['repair','quick','diagnose','quick-protocol http2',
  'quick-autostart status','quick-autostart enable','quick-autostart status','quick-autostart disable','quick-autostart status',
  'logs singbox','logs quick','logs named','restart','diagnose'],node_routes
 assert '快捷隧道' in node_routes and '固定隧道' in node_routes,node_routes
 assert '一键安装节点' not in node_routes and (node_state.read_bytes(),node_state.stat().st_ino)==saved_node
 cf_calls=HOME/'cf-actions'
 code,cf_routes=execute(CLI/'ibt.sh',[],[
  ('请选择','3'),('优选节点地址','8'),('查看上次结果','1'),('按回车返回',''),
  ('查看上次结果','2'),('按回车返回',''),('查看上次结果','0'),
  ('优选节点地址','0'),('请选择','0')])
 assert code==0 and cf_calls.read_text().splitlines()==['','--show-last'],cf_routes
 assert (node_state.read_bytes(),node_state.stat().st_ino)==saved_node
 code,cf_cli=execute(CLI/'ibt.sh',['cf','--show-last'])
 assert code==0 and 'CF_ACTION:--show-last' in cf_cli,cf_cli
 core_calls.write_text('')
 code,repair_routes=execute(CLI/'ibt.sh',[],[
  ('请选择','3'),('修复现有节点','1'),('返回节点管理','4'),
  ('返回节点管理','2'),('重建临时隧道会使旧地址失效','n'),
  ('返回节点管理','3'),('重建临时隧道会使旧地址失效','y'),('按回车返回',''),
  ('修复现有节点','1'),('返回节点管理','1'),('按回车返回',''),
  ('修复现有节点','1'),('返回节点管理','0'),('按回车返回',''),
  ('修复现有节点','0'),('请选择','0')],{'MOCK_REPAIR_FAIL':'1'})
 assert code==0,repair_routes
 assert core_calls.read_text().splitlines()==['repair','logs singbox','quick-protocol http2','repair','diagnose','repair'],repair_routes
 assert (node_state.read_bytes(),node_state.stat().st_ino)==saved_node
 core_calls.write_text('')
 code,cancelled=execute(CLI/'ibt.sh',[],[
  ('请选择','7'),('卸载管理工具','2'),('删除本工具的节点服务和管理菜单','n'),
  ('按回车返回',''),('卸载管理工具','0'),('请选择','0')])
 assert code==0 and '已取消。' in cancelled,cancelled
 assert '本机名称：' in cancelled.split('已取消。',1)[1],'Cancelling uninstall must leave the main menu available'
 assert core_calls.read_text()=='' and key.read_text().strip()==DUMMY
 assert (node_state.read_bytes(),node_state.stat().st_ino)==saved_node
 # Every optimization action is delegated to a stub; no sudo/sysctl/swap tools
 # can run in this menu test. Merely opening the page only reads status.
 opt_calls=HOME/'optimization-actions'
 code,opt_read=execute(CLI/'ibt.sh',[],[('请选择','6'),('恢复原有设置','0'),('请选择','0')])
 assert code==0 and opt_calls.read_text().splitlines()==['status'],opt_read
 opt_calls.write_text('')
 code,opt_routes=execute(CLI/'ibt.sh',[],[
  ('请选择','6'),('恢复原有设置','1'),('按回车返回',''),
  ('恢复原有设置','2'),('按回车返回',''),
  ('恢复原有设置','3'),('关闭工具交换','1'),('按回车返回',''),
  ('关闭工具交换','2'),('交换容量（MiB',''),('按回车返回',''),
  ('关闭工具交换','2'),('交换容量（MiB','2048'),('按回车返回',''),
  ('关闭工具交换','3'),('按回车返回',''),('关闭工具交换','0'),
  ('恢复原有设置','4'),('恢复原有参数','1'),('按回车返回',''),
  ('恢复原有参数','2'),('按回车返回',''),('恢复原有参数','0'),
  ('恢复原有设置','5'),('按回车返回',''),('恢复原有设置','0'),('请选择','0')])
 assert code==0,opt_routes
 assert [call for call in opt_calls.read_text().splitlines() if call!='status']==[
  'recommend','apply','swap-on','swap-on 2048','swap-off','bbr-on','bbr-off','restore'],opt_routes
 assert (node_state.read_bytes(),node_state.stat().st_ino)==saved_node
 code,auth_status=execute('ibt.sh',['key','status'],extra={'NODE_MUST_NOT_RUN':'1'})
 assert code==0 and DUMMY not in auth_status and '输入' not in auth_status,auth_status
 code,_=execute('keepalive.sh',['key-forget'])
 assert code==0 and not key.exists()
 code,status=execute('ibt.sh',['keepalive','status'],extra={'NODE_MUST_NOT_RUN':'1'})
 assert code==0 and '输入 InstaBox' not in status and '准备官方管理组件' not in status,status
 assert not key.exists(), 'Viewing an unconfigured heartbeat must not ask for or cache an API key'
 code,heartbeat_status=execute('ibt.sh',[],[
  ('请选择','4'),('查看保活详情','7'),('按回车返回',''),('查看保活详情','0'),('请选择','0')],{'NODE_MUST_NOT_RUN':'1'})
 assert code==0 and '输入 InstaBox' not in heartbeat_status and not key.exists(),heartbeat_status
 code,heartbeat_logs=execute('ibt.sh',[],[
  ('请选择','4'),('查看保活详情','3'),('查看保活日志','4'),('按回车返回',''),
  ('查看保活日志','0'),('查看保活详情','0'),('请选择','0')])
 assert code==0 and 'JOURNAL_ACTION:' in heartbeat_logs,heartbeat_logs
 assert 'insta-box-heartbeat.service' in (HOME/'journal-actions').read_text()

 # The menu remains usable when its automatic read-only status is unavailable.
 # Stub only this installed copy's command delegate; the credential checks above
 # and below still use the real runtime and never contact an endpoint.
 platform_calls=HOME/'platform-actions'
 (CLI/'keepalive.sh').write_text('''#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$HOME/platform-actions"
if [[ "${1:-}" == status ]]; then
  printf '%s\\n' '保活目标： 尚未配置' '下次执行： 尚未安排'
  if [[ "${MOCK_MENU_STATUS_FAIL:-0}" == 1 ]]; then
    printf '%s\\n' '状态暂不可读取'
    exit 2
  fi
else printf 'PLATFORM_ACTION:%s\\n' "$*"; fi
''')
 code,auto_route=execute(CLI/'ibt.sh',[],[
  ('请选择','4'),('查看保活详情','1'),('按回车返回',''),('查看保活详情','0'),('请选择','0')])
 assert code==0 and '一键保活机器' in auto_route and 'PLATFORM_ACTION:auto' in auto_route,auto_route
 assert platform_calls.read_text().splitlines()==['status --brief','auto','status --brief'],auto_route
 platform_calls.write_text('')
 cloud_before=(HOME/'cloud-actions').read_text().splitlines()
 code,target_routes=execute(CLI/'ibt.sh',[],[
  ('请选择','4'),('查看保活详情','2'),('清除保活配置','1'),('按回车返回',''),
  ('清除保活配置','2'),('按回车返回',''),('清除保活配置','3'),('按回车返回',''),
  ('清除保活配置','4'),('停用本机保活并清除保活目标与临时凭据','n'),('按回车返回',''),
  ('清除保活配置','0'),('查看保活详情','7'),('按回车返回',''),('查看保活详情','0'),('请选择','0')],{'MOCK_MENU_STATUS_FAIL':'1'})
 assert code==0 and '状态暂不可读取' in target_routes,target_routes
 actions=platform_calls.read_text().splitlines()
 assert actions==['status --brief','add','remove','status --brief','status','status --brief'],actions
 assert (HOME/'cloud-actions').read_text().splitlines()[len(cloud_before):]==['protect on'],target_routes
 assert not key.exists() and not (key.parent/'heartbeat.json').exists(),'Read-only status or a cancelled clear changed credentials'
 platform_calls.write_text('')
 code,task_routes=execute(CLI/'ibt.sh',[],[
  ('请选择','4'),('查看保活详情','3'),('查看保活日志','1'),('按回车返回',''),
  ('查看保活日志','2'),('按回车返回',''),('查看保活日志','3'),('按回车返回',''),
  ('查看保活日志','4'),('按回车返回',''),('查看保活日志','0'),
  ('查看保活详情','5'),('查看平台策略','1'),('按回车返回',''),
  ('查看平台策略','2'),('按回车返回',''),('查看平台策略','0'),('查看保活详情','0'),('请选择','0')])
 assert code==0,task_routes
 assert [action for action in platform_calls.read_text().splitlines() if action not in ('status','status --brief')]==[
  'run','start','stop','logs','apply','check'],task_routes
 platform_calls.write_text('')
 cloud_before=(HOME/'cloud-actions').read_text().splitlines()
 cross_routes=[('请选择','4')]
 for _ in range(10):
  cross_routes.extend([('查看保活详情','6'),('刷新机器列表','8')])
 cross_routes.extend([('查看保活详情','0'),('本机名称：','0')])
 code,crossed=execute(CLI/'ibt.sh',[],cross_routes,{'FUNCNEST':'16'})
 assert code==0 and plain_text(crossed).count('本机名称：')==2,crossed
 assert (HOME/'cloud-actions').read_text().splitlines()[len(cloud_before):]==['overview']*10,crossed
 assert platform_calls.read_text().splitlines()==['status --brief']*11,'Cross-page navigation must only read brief status'
 code,cloud_return=execute(CLI/'ibt.sh',[],[
  ('请选择','4'),('查看保活详情','6'),('刷新机器列表','0'),('本机名称：','0')])
 assert code==0 and plain_text(cloud_return).count('本机名称：')==2,cloud_return
 assert plain_text(cloud_return).count('查看保活详情')==1,'Cloud 0 must return home without reopening its previous page'
 ssh_token='ibssh_FAKE_PTY_ONLY'
 command='mosh --ssh="ssh -p 2222" '+ssh_token+'@api.instabox.sh'
 code,ssh_setup=execute('ibt.sh',['keepalive','setup-ssh'],[
  ('粘贴 SSH/Mosh 命令',command),('目标名称','PTY VM'),('预计剩余小时','24'),
  ('粘贴 SSH/Mosh 命令',''),('检查间隔','')],{'NODE_MUST_NOT_RUN':'1'})
 assert code==0,ssh_setup
 assert ssh_token not in ssh_setup and command not in ssh_setup,ssh_setup
 assert not key.exists(), 'SSH-only setup must not create an API key'
 config_file=key.parent/'heartbeat.json'
 config=json.loads(config_file.read_text())
 assert config['targets'][0]['ssh']['user']==ssh_token
 assert config['targets'][0]['ssh']['port']==2222
 assert stat.S_IMODE(config_file.stat().st_mode)==0o600
 unit=HOME/'.config/systemd/user/insta-box-heartbeat.service'
 assert '%h/.local/share/insta-box/cli/heartbeat.py' in unit.read_text()
 assert ssh_token not in unit.read_text()
 core_calls.write_text('')
 code,removed=execute(CLI/'ibt.sh',[],[
  ('请选择','7'),('卸载管理工具','2'),('删除本工具的节点服务和管理菜单','y')])
 assert code==0 and '本机卸载完成。' in removed,removed
 assert core_calls.read_text().splitlines()==['uninstall']
 assert '本机名称：' not in removed.split('本机卸载完成。',1)[1],'Successful uninstall must exit the menu'
 assert not (HOME/'unexpected-network').exists(),'A menu smoke attempted an external request'
 print('Private API/SSH input, SSH-only setup, safe node/uninstall routes, grouped heartbeat/cloud actions, read-only brief/detail status, bounded cross-page navigation, colors, NO_COLOR, and SDK-free status: passed')
finally:shutil.rmtree(TMP,ignore_errors=True)

# Main labels use four characters; action labels in submenus use six.
source=(ROOT/'ibt.sh').read_text()
main=re.search(r'^main_menu\(\) \{\n.*?^\}',source,re.M|re.S)
assert main,'Main menu function is missing'
main_labels=re.findall(r"item\s+\d+\s+'([^']+)'",main.group())
sub_labels=re.findall(r"item\s+\d+\s+'([^']+)'",source[:main.start()]+source[main.end():])
assert main_labels and all(len(label)==4 for label in main_labels),main_labels
assert sub_labels and all(len(label)==6 for label in sub_labels),sub_labels
known_labels=set(main_labels+sub_labels)
seen_labels=set()
for transcript in MENU_TRANSCRIPTS:
 for line in plain_text(transcript).splitlines():
  item=re.match(r'^\s*\d+\.(\s+)([^\r\n]+)$',line)
  if item and item.group(2) in known_labels:
   assert item.group(1)==' ',line
   seen_labels.add(item.group(2))
assert seen_labels==known_labels,known_labels-seen_labels
print('Main labels are four characters; submenu labels are six characters; every menu uses one space after the number')
