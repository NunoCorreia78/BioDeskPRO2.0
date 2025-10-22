$filePath = "c:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\src\BioDesk.ViewModels\Abas\ComunicacaoViewModel.cs"
$content = Get-Content $filePath -Raw -Encoding UTF8

# Encontrar e substituir o bloco crítico
$pattern = @'
            var resultado = await _emailService\.EnviarAsync\(emailMessage\);

            // .* CORREÇÃO: Usar scope isolado para DbContext
            using var scope2 = _scopeFactory\.CreateScope\(\);
            var dbContext2 = scope2\.ServiceProvider\.GetRequiredService<BioDeskDbContext>\(\);

            // Criar comunicação na DB com STATUS CORRETO desde o início
            var comunicacao = new Comunicacao
'@

$replacement = @'
            _logger.LogWarning("📧 [ComunicacaoViewModel] Tentando enviar email IMEDIATO para {Email}...", Destinatario);

            var resultado = await _emailService.EnviarAsync(emailMessage);

            // ✅ CORREÇÃO CRÍTICA: Só grava na BD se ENVIOU COM SUCESSO ou se está SEM INTERNET
            // Se falhou por erro SMTP → NÃO gravar na BD (mostrar erro e parar)

            if (!resultado.Sucesso && !resultado.AdicionadoNaFila)
            {
                // ❌ ERRO SMTP (autenticação, credenciais, etc.) - NÃO AGENDAR!
                ErrorMessage = resultado.Mensagem ?? "Erro desconhecido ao enviar email.";
                _logger.LogError("❌ Email FALHOU e NÃO foi agendado: {Erro}", resultado.Mensagem);
                IsLoading = false;
                return; // ⚠️ PARAR AQUI - Não gravar na BD
            }

            // ✅ Se chegou aqui: ou enviou com sucesso OU está sem internet (agendado)

            // ⚡ CORREÇÃO: Usar scope isolado para DbContext
            using var scope2 = _scopeFactory.CreateScope();
            var dbContext2 = scope2.ServiceProvider.GetRequiredService<BioDeskDbContext>();

            // Criar comunicação na DB com STATUS CORRETO desde o início
            var comunicacao = new Comunicacao
'@

$content = $content -replace $pattern, $replacement

# Substituir UltimoErro
$content = $content -replace '(TentativasEnvio = resultado\.Sucesso \? 0 : 1,\s+)UltimoErro = resultado\.Sucesso \? null : resultado\.Mensagem', '$1UltimoErro = resultado.Sucesso ? null : "Sem conexão à internet"'

# Substituir bloco de mensagens de feedback
$pattern2 = @'
            // Mensagem de feedback conforme resultado
            if \(resultado\.Sucesso\)
            \{
                SuccessMessage = ".*?";
                _logger\.LogInformation\(".*?", comunicacao\.Id, comunicacao\.Status\);
            \}
            else
            \{
                if \(resultado\.AdicionadoNaFila\)
                \{
                    SuccessMessage = ".*?";
                    _logger\.LogWarning\(".*?", comunicacao\.Id, comunicacao\.Status\);
                \}
                else
                \{
                    SuccessMessage = \$?".*?";
                    _logger\.LogWarning\(".*?", comunicacao\.Id, resultado\.Mensagem, comunicacao\.Status\);
                \}
            \}
'@

$replacement2 = @'
            // ✅ Mensagem de feedback conforme resultado
            if (resultado.Sucesso)
            {
                SuccessMessage = "✅ Email enviado com sucesso!";
                _logger.LogInformation("✅ Email ID {Id} enviado IMEDIATAMENTE (Status={Status})", comunicacao.Id, comunicacao.Status);
            }
            else if (resultado.AdicionadoNaFila)
            {
                // Sem internet → Agendado para retry automático
                SuccessMessage = "⚠️ Sem conexão. Email agendado para envio automático quando houver internet.";
                _logger.LogWarning("⚠️ Email ID {Id} agendado (sem rede, Status={Status})", comunicacao.Id, comunicacao.Status);
            }
'@

$content = $content -replace $pattern2, $replacement2

Set-Content $filePath $content -Encoding UTF8 -NoNewline
Write-Host "✅ ComunicacaoViewModel.cs atualizado com correção crítica!"
