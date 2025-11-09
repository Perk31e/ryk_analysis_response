# Get-AuthenticodeSignature cmdlet 사용
$signature = Get-AuthenticodeSignature "c:\windows\system32\fodhelper.exe"
$signature.Status
$signature.StatusMessage
$signature.SignerCertificate

# 상태 값 해석:
# - Valid: 유효한 서명
# - Invalid: 무효한 서명
# - NotSigned: 서명 없음
# - HashMismatch: 파일이 변조됨
# - NotTrusted: 신뢰할 수 없는 인증서
# - UnknownError: 알 수 없는 오류