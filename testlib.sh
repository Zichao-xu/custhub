# 验收脚本共用: 发通行证(design-v3 §0 第 11 条)
#   mkpass <主钥匙私钥> <输出文件> <发给谁的公钥> <to: all | 公钥…> <svc> [生效偏移秒 默认 -60] [到期偏移秒 默认 3600]
mkpass(){
  local mk=$1 out=$2 key=$3 to=$4 svc=$5 f=${6:--60} u=${7:-3600}
  local tf tu; read -r tf tu < <(python3 -c "import time,sys; n=time.time(); g=lambda o: time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(n+int(o))); print(g(sys.argv[1]), g(sys.argv[2]))" "$f" "$u")
  printf 'custhub-pass v1\nkey %s\nto %s\nsvc %s\nfrom %s\nuntil %s\n--end--\n' "$key" "$to" "$svc" "$tf" "$tu" >"$out.body"
  ssh-keygen -q -Y sign -f "$mk" -n custhub-pass "$out.body" 2>/dev/null
  cat "$out.body" "$out.body.sig" >"$out.tmp"; rm -f "$out.body" "$out.body.sig"; mv "$out.tmp" "$out"
}
