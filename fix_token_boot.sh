#!/bin/bash
# Script para resolver o problema do token não ligar automaticamente no boot
# Deve ser executado com sudo

if [ "$EUID" -ne 0 ]; then
  echo "Por favor, rode este script com sudo."
  exit 1
fi

echo "Configurando o pcscd para iniciar automaticamente no boot (não apenas sob demanda)..."
systemctl enable pcscd.service

echo "Criando o script de despertar do token..."
cat << 'EOF' > /usr/local/bin/wake-token.sh
#!/bin/bash
# Acorda o token A3 forçando uma leitura no PC/SC durante o boot
for i in {1..5}; do
  /usr/local/bin/opensc-tool -l > /dev/null 2>&1
  sleep 1
done
EOF
chmod +x /usr/local/bin/wake-token.sh

echo "Criando o serviço systemd para rodar o script no boot..."
cat << 'EOF' > /etc/systemd/system/wake-token.service
[Unit]
Description=Wake up Smart Card Token
After=pcscd.service
Requires=pcscd.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/wake-token.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

echo "Ativando e iniciando o serviço..."
systemctl daemon-reload
systemctl enable wake-token.service
systemctl start wake-token.service

echo ""
echo "=== FEITO! ==="
echo "O seu token agora vai ligar e inicializar automaticamente junto com o Debian."
echo "Pode reiniciar a máquina e testar o sudo logo em seguida, o erro não deve mais ocorrer."
