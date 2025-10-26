using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using BioDesk.ViewModels.Abas;

namespace BioDesk.App.Views.Abas
{
    public partial class ConsentimentosUserControl : UserControl
    {
        private readonly Dictionary<string, ConsentimentoTemplate> _templates;
        private bool _isDrawing = false;
        private bool _hasSignature = false;
        private Polyline? _currentStroke = null;

        public ConsentimentosUserControl()
        {
            InitializeComponent();
            Loaded += OnLoaded;
            _templates = new Dictionary<string, ConsentimentoTemplate>();
            InicializarTemplates();
        }

        private void OnLoaded(object sender, RoutedEventArgs e)
        {
            // Subscrever eventos de mudança em todos os controles
            SubscribeToControlChanges(this);
        }

        /// <summary>
        /// Subscrever recursivamente a mudanças em TextBox, ComboBox e CheckBox
        /// </summary>
        private void SubscribeToControlChanges(DependencyObject parent)
        {
            int childCount = System.Windows.Media.VisualTreeHelper.GetChildrenCount(parent);
            for (int i = 0; i < childCount; i++)
            {
                var child = System.Windows.Media.VisualTreeHelper.GetChild(parent, i);

                if (child is TextBox textBox)
                {
                    textBox.TextChanged -= OnControlValueChanged;
                    textBox.TextChanged += OnControlValueChanged;
                }
                else if (child is ComboBox comboBox)
                {
                    comboBox.SelectionChanged -= OnControlValueChanged;
                    comboBox.SelectionChanged += OnControlValueChanged;
                }
                else if (child is CheckBox checkBox)
                {
                    checkBox.Checked -= OnControlValueChanged;
                    checkBox.Unchecked -= OnControlValueChanged;
                    checkBox.Checked += OnControlValueChanged;
                    checkBox.Unchecked += OnControlValueChanged;
                }

                SubscribeToControlChanges(child);
            }
        }

        private void OnControlValueChanged(object sender, RoutedEventArgs e)
        {
            var window = Window.GetWindow(this);
            if (window?.DataContext is BioDesk.ViewModels.FichaPacienteViewModel viewModel)
            {
                viewModel.MarcarComoAlterado();
            }
        }

        private void InicializarTemplates()
        {
            _templates.Add("naturopatia", new ConsentimentoTemplate
            {
                Titulo = "🌿 CONSENTIMENTO INFORMADO - NATUROPATIA",
                Texto = @"NATUREZA DO TRATAMENTO:
A Naturopatia é uma abordagem terapêutica complementar reconhecida que trabalha em harmonia com os mecanismos naturais de autocura do organismo, através de métodos como fitoterapia, nutrição funcional, hidroterapia e técnicas de equilibração energética. Em situações agudas graves ou emergências médicas, o paciente deve procurar tratamento médico convencional imediatamente.

BENEFÍCIOS ESPERADOS:
• Melhoria do bem-estar geral e qualidade de vida
• Fortalecimento do sistema imunitário
• Redução de sintomas crónicos e incapacidade
• Equilíbrio energético e homeostase do organismo
• Prevenção de doenças através de abordagem holística
• Aumento de vitalidade e resistência

RISCOS E EFEITOS POSSÍVEIS:
• Reações alérgicas a produtos naturais (raras, quando há predisposição)
• Interações com medicamentos convencionais (informar SEMPRE todos os medicamentos)
• Tempo de resposta variável (3-12 semanas conforme o organismo)
• Possível agravação temporária antes da melhoria (resposta terapêutica natural)
• Fadiga temporária durante processo de desintoxicação
• Efeitos individuais variam conforme predisposição constitucional

CONTRAINDICAÇÕES E PRECAUÇÕES:
• Gravidez e amamentação (alguns produtos específicos)
• Alergias conhecidas a plantas ou substâncias naturais
• Doenças graves em fase aguda (avaliar caso a caso)
• Distúrbios graves de coagulação ou uso de anticoagulantes (alguns produtos)
• Condições psiquiátricas graves sem supervisão médica
• Pacientes que não conseguem manter seguimento médico regular

RESPONSABILIDADES DO PACIENTE - INFORMAÇÕES CRÍTICAS:
• Informar COMPLETAMENTE sobre toda medicação atual (prescrição e sem receita)
• Comunicar todas as alergias conhecidas - plantas, alimentos, substâncias
• Informar imediatamente sobre gravidez confirmada ou suspeita
• Reportar qualquer interação ou reação adversa ao terapeuta
• Manter seguimento médico convencional se necessário para confirmar diagnósticos
• Procurar imediatamente médico em caso de sintomas agudos ou emergência
• Seguir integralmente as recomendações e posologia indicadas
• Não interromper medicação prescrita sem orientação médica
• Comunicar mudanças no estado de saúde ou novos sintomas

DURAÇÃO E FREQUÊNCIA:
• Tratamentos variam de 3 semanas a 6 meses conforme condição
• Resultados podem ser graduais e requerem consistência
• Reavaliação recomendada a cada 4 semanas"
            });

            _templates.Add("osteopatia", new ConsentimentoTemplate
            {
                Titulo = "🦴 CONSENTIMENTO INFORMADO - OSTEOPATIA",
                Texto = @"NATUREZA DO TRATAMENTO:
A Osteopatia é uma terapia manual complementar de grande valor que utiliza técnicas específicas de mobilização, manipulação articular e mobilização de tecidos moles para restabelecer o equilíbrio estrutural e funcional do corpo. Em casos de trauma agudo, suspeita de fratura ou emergência médica, o paciente deve procurar primeiro avaliação médica.

BENEFÍCIOS ESPERADOS:
• Alívio eficaz de dores musculoesqueléticas
• Melhoria significativa da mobilidade articular
• Redução de tensões musculares e enrijecimentos
• Melhoria da postura e alinhamento corporal
• Alívio de cefaleias tensionais e de origem cervical
• Melhoria geral da qualidade de vida funcional
• Prevenção de lesões através de reequilíbrio

RISCOS E EFEITOS POTENCIAIS:
• Dor musculoesquelética temporária após o tratamento (normal e esperado)
• Rigidez temporária (24-48h) antes de melhoria duradoura
• Possível agravação temporária de sintomas existentes (resposta terapêutica)
• Raramente: irritação de raízes nervosas
• Muito raramente: complicações vasculares (em pacientes com patologias vasculares)

CONTRAINDICAÇÕES E PRECAUÇÕES:
• Fraturas recentes (menos de 6 semanas)
• Infeções agudas na área a tratar
• Tumores malignos na área (avaliação médica prévia necessária)
• Osteoporose severa diagnosticada
• Artrite reumatoide em fase aguda inflamatória
• Trombose venosa profunda ou embolia
• Tratamento anticoagulante agressivo
• Síndrome da cauda equina

RESPONSABILIDADES DO PACIENTE - INFORMAÇÕES CRÍTICAS:
• Informar COMPLETAMENTE sobre toda medicação atual
• Comunicar todas as condições médicas, mesmo que aparentemente não relacionadas
• Avisar imediatamente sobre gravidez
• Reportar qualquer dor anormal ou desconforto durante o tratamento
• Comunicar se tem hematomas fáceis ou distúrbios de coagulação
• Seguir rigorosamente os exercícios e recomendações post-tratamento
• Informar sobre qualquer reação adversa inesperada
• Procurar médico em caso de trauma ou agravamento súbito

DURAÇÃO E FREQUÊNCIA:
• Tratamentos iniciais geralmente 4-6 sessões
• Espaçamento de 7-14 dias entre sessões conforme resposta
• Reavaliação após 3 sessões
• Manutenção pode variar de mensal a trimestral"
            });

            _templates.Add("acupunctura", new ConsentimentoTemplate
            {
                Titulo = "🪡 CONSENTIMENTO INFORMADO - ACUPUNCTURA",
                Texto = @"NATUREZA DO TRATAMENTO:
A Acupunctura é uma técnica terapêutica milenar da Medicina Tradicional Chinesa com eficácia cientificamente comprovada, que utiliza agulhas estéreis muito finas inseridas em pontos específicos do corpo para equilibrar a energia vital (Qi) e restaurar a saúde. Em situações de urgência médica ou emergência, o paciente deve procurar atendimento médico imediatamente.

BENEFÍCIOS ESPERADOS:
• Alívio eficaz da dor crónica de múltiplas origens
• Redução significativa de stress e ansiedade
• Melhoria substancial da qualidade do sono
• Regulação de funções orgânicas e homeostase
• Fortalecimento do sistema imunitário e resistência
• Melhoria do bem-estar emocional e mental
• Aumento de energia e vitalidade

RISCOS E EFEITOS POTENCIAIS:
• Dor ligeira ou leve no local de inserção das agulhas (normal)
• Pequenos hematomas nos pontos de inserção (raros e resolvem naturalmente)
• Raramente: infeção local (agulhas são estéreis descartáveis)
• Muito raramente: pneumotórax em punção torácica (técnico experiente evita)
• Possível sonolência pós-tratamento (indicador de resposta terapêutica positiva)
• Possível relaxamento profundo ou ligeiras emoções liberadas

CONTRAINDICAÇÕES E PRECAUÇÕES:
• Distúrbios graves de coagulação diagnosticados
• Uso de anticoagulantes agressivos (marcar com médico)
• Gravidez (alguns pontos evitados, outros seguros)
• Infeções cutâneas agudas na área a tratar
• Estados febris agudos ativos
• Pacientes com fobia extrema de agulhas (conversa prévia recomendada)
• Implantes metálicos na área (geralmente sem problema)

RESPONSABILIDADES DO PACIENTE - INFORMAÇÕES CRÍTICAS:
• Informar IMEDIATAMENTE sobre qualquer medicação anticoagulante
• Comunicar gravidez confirmada ou suspeita
• Avisar sobre medo extremo de agulhas
• Informar sobre alergias ao álcool ou iodo (desinfetante)
• Comunicar qualquer reação adversa inesperada
• Relaxar e respirar profundamente durante o tratamento
• Evitar refeições pesadas 1-2h antes da sessão
• Manter hidratação adequada pós-tratamento

DURAÇÃO E FREQUÊNCIA:
• Sessões variam de 20-45 minutos conforme protocolo
• Tratamentos agudos: 1-3 vezes/semana
• Tratamentos crónicos: 1-2 vezes/semana por 4-12 semanas
• Reavaliação recomendada a cada 5-6 sessões
• Manutenção: mensal a trimestral conforme caso"
            });

            _templates.Add("massagem", new ConsentimentoTemplate
            {
                Titulo = "💆 CONSENTIMENTO INFORMADO - MASSAGEM TERAPÊUTICA",
                Texto = @"NATUREZA DO TRATAMENTO:
A Massagem Terapêutica é uma técnica manual eficaz que utiliza técnicas específicas de manipulação de tecidos moles para tratar tensões musculares, melhorar a circulação sanguínea e promover relaxamento profundo e bem-estar geral. Em caso de lesão aguda, suspeita de fratura ou emergência médica, o paciente deve procurar avaliação médica primeiro.

BENEFÍCIOS ESPERADOS:
• Alívio eficaz de tensões musculares e enrijecimentos
• Melhoria significativa da circulação sanguínea e linfática
• Redução profunda do stress e ansiedade
• Relaxamento muscular e mental completo
• Melhoria substancial da qualidade do sono
• Aumento de flexibilidade e amplitude de movimento
• Melhoria geral do bem-estar e vitalidade

RISCOS E EFEITOS POTENCIAIS:
• Dor ligeira durante ou após a massagem (resposta terapêutica normal)
• Hematomas ligeiros (raros, indicam libertação de toxinas)
• Reações cutâneas leves a óleos específicos (informar de alergias)
• Tonturas ligeiras após a sessão (normaliza-se rapidamente)
• Possível liberação emocional ou reações emocionais (natural e seguro)
• Fadiga ligeira pós-sessão (sinal de desintoxicação)

CONTRAINDICAÇÕES E PRECAUÇÕES:
• Infeções ou feridas abertas na pele da área
• Trombose venosa profunda diagnosticada
• Fraturas recentes (menos de 6 semanas)
• Certas condições cardíacas graves (consultar médico)
• Cirurgias recentes (menos de 4 semanas)
• Varicoses severas (aplicar cuidados especiais)
• Hematomas recentes ou grandes

RESPONSABILIDADES DO PACIENTE - INFORMAÇÕES CRÍTICAS:
• Informar COMPLETAMENTE sobre todas as condições médicas
• Comunicar todas as alergias a produtos, plantas ou substâncias
• Avisar imediatamente sobre gravidez
• Indicar claramente áreas sensíveis, dolorosas ou com lesões
• Comunicar desconforto ou dor durante o tratamento
• Informar sobre medicação atual e problemas de coagulação
• Relatar qualquer reação adversa inesperada
• Manter comunicação constante com o terapeuta

DURAÇÃO E FREQUÊNCIA:
• Sessões variam de 30-90 minutos conforme tipo
• Tratamentos agudos: 2-3 vezes/semana
• Tratamentos crónicos: 1-2 vezes/semana
• Manutenção: mensal a quinzenal
• Reavaliação recomendada a cada 3-4 sessões"
            });

            _templates.Add("bioenergetica", new ConsentimentoTemplate
            {
                Titulo = "🧘 CONSENTIMENTO INFORMADO - TERAPIA BIOENERGÉTICA",
                Texto = @"NATUREZA DO TRATAMENTO:
A Terapia Bioenergética é uma abordagem complementar que trabalha com o campo energético do organismo através de técnicas de harmonização e equilíbrio da energia vital, promovendo reequilíbrio profundo e bem-estar holístico. Em situações de urgência médica ou crise emocional grave, o paciente deve procurar atendimento profissional apropriado imediatamente.

BENEFÍCIOS ESPERADOS:
• Equilíbrio energético geral profundo
• Redução significativa de stress e tensão
• Melhoria substancial do bem-estar emocional
• Harmonização dos centros energéticos (chakras)
• Aumento de vitalidade, energia e resistência
• Melhoria do desempenho e clareza mental
• Alívio de bloqueios energéticos e emocionais

LIMITAÇÕES E ESCLARECIMENTOS IMPORTANTES:
• Resultados variam significativamente entre indivíduos
• NÃO é diagnóstico médico - é complementar
• NÃO substitui medicação prescrita ou tratamento convencional
• Abordagem holística, requer abertura e participação ativa
• Não há cura mágica - requer compreensão e consistência
• Pode revelar padrões emocionais profundos (reação natural)

POSSÍVEIS REAÇÕES E EFEITOS:
• Sensação de profundo relaxamento ou cansaço (normal)
• Possível liberação emocional (choro, riso) - seguro e recomendado
• Sensações corporais intensas (formigueiro, calor) - normais
• Sonhos vívidos nos dias seguintes (processamento energético)
• Possível aumento temporário de consciência sobre problemas
• Rara: desconforto físico durante o processo

CONTRAINDICAÇÕES E PRECAUÇÕES:
• Situações de crise psicológica aguda grave
• Transtornos psiquiátricos severos sem supervisão médica
• Estados delirantes ou alucinações ativas
• Pacientes em abuso de substâncias ou alcoolismo
• Resistência extrema à abordagem (necessária abertura)

RESPONSABILIDADES DO PACIENTE - INFORMAÇÕES CRÍTICAS:
• Informar sobre todas as condições psicológicas ou psiquiátricas
• Comunicar medicação psiquiátrica ou psicoativa em uso
• Ser completamente honesto sobre estado emocional
• Participar ativamente no processo de cura
• Manter comunicação aberta durante as sessões
• Não interromper medicação prescrita sem conselho médico
• Reportar qualquer desconforto emocional significativo
• Estar aberto a mudanças pessoais e transformação

DURAÇÃO E FREQUÊNCIA:
• Sessões variam de 45-90 minutos conforme sessão
• Tratamentos iniciais: semanal por 4-6 semanas
• Manutenção: quinzenal a mensal
• Reavaliação recomendada a cada 4-6 sessões
• Repouso adequado recomendado após sessões"
            });

            // ===== NOVAS TÉCNICAS ESPECIALIZADAS =====

            _templates.Add("iridologia", new ConsentimentoTemplate
            {
                Titulo = "👁️ CONSENTIMENTO INFORMADO - IRIDOLOGIA",
                Texto = @"NATUREZA DO EXAME:
A Iridologia é uma técnica complementar de análise da íris ocular que avalia a constituição individual e identifica predisposições constitucionais, complementando avaliações convencionais de saúde. É fundamental compreender que iridologia não é diagnóstico médico, mas uma ferramenta de orientação preventiva. Qualquer suspeita de doença deve ser confirmada por profissional médico.

PROCEDIMENTO:
• Observação detalhada e cuidadosa da íris ocular
• Possivelmente fotografia profissional da íris (com consentimento explícito)
• Análise de padrões, cores, marcas e estruturas
• Correlação com mapa iridológico internacional
• Elaboração de relatório informativo e recomendações

INFORMAÇÕES IMPORTANTES SOBRE LIMITAÇÕES:
• NÃO é um diagnóstico médico - é análise constitucional
• NÃO substitui exames clínicos ou imagiológicos convencionais
• Indica tendências constitucionais e predisposições
• Ferramenta de avaliação complementar e preventiva
• Não detecta doenças específicas ou laboratoriais
• Não substitui opinião médica em patologias agudas

BENEFÍCIOS ESPERADOS:
• Compreensão da constituição individual profunda
• Identificação de predisposições de saúde
• Orientação para medidas preventivas personalizadas
• Integração com outras abordagens complementares
• Melhor compreensão de padrões de saúde pessoais
• Base para recomendações nutricionais e estilo de vida

RESPONSABILIDADES DO PACIENTE - INFORMAÇÕES CRÍTICAS:
• Manter seguimento médico regular obrigatório
• Não interromper medicação prescrita
• Usar informações como orientação preventiva apenas
• Procurar imediatamente médico para sintomas específicos
• Entender que recomendações são complementares
• Comunicar qualquer mudança significativa de saúde ao médico
• Não adiar consultas médicas baseado em análise iridológica

PROTEÇÃO DE DADOS E PRIVACIDADE:
• Imagens armazenadas com máxima segurança
• Uso exclusivo para análise iridológica pessoal
• Não partilha com terceiros sem autorização explícita
• Arquivo mantido conforme regulamentação RGPD
• Direito a acesso, retificação e apagamento de imagens
• Destruição de imagens possível a qualquer momento

DURAÇÃO E FREQUÊNCIA:
• Sessão inicial: 45-60 minutos
• Reavaliações: 30-45 minutos
• Recomendado: reavaliação anual ou conforme mudanças
• Melhor em conjunto com outras abordagens
• Integrar com historial médico e laboratorial disponível"
            });

            _templates.Add("mesoterapia", new ConsentimentoTemplate
            {
                Titulo = "💉 CONSENTIMENTO INFORMADO - MESOTERAPIA HOMEOPÁTICA",
                Texto = @"NATUREZA DO TRATAMENTO:
A Mesoterapia Homeopática é uma técnica especializada que combina princípios homeopáticos com aplicação localizada através de micro-injeções dérmicas superficiais em pontos específicos, maximizando eficácia local com mínimos efeitos sistémicos. Em caso de reação adversa inesperada ou deterioração significativa, o paciente deve contactar o terapeuta ou procurar atendimento médico.

PROCEDIMENTO DETALHADO:
• Avaliação e marcação dos pontos específicos
• Preparação e desinfeção rigorosa da área
• Aplicação de agulhas muito finas (4-6mm) e descartáveis
• Injeção precisa de preparados homeopáticos
• Possível aplicação de compressas ou técnicas complementares
• Observação pós-aplicação imediata

BENEFÍCIOS ESPERADOS:
• Ação localizada eficaz do medicamento
• Estimulação precisa de pontos específicos
• Melhoria da circulação local e drenagem
• Redução efetiva de inflamação localizada
• Harmonização energética local profunda
• Redução de volume e adiposidade (em aplicações cosméticas)
• Melhoria da qualidade da pele

RISCOS E EFEITOS POTENCIAIS:
• Dor leve no local de aplicação (normal e esperado)
• Pequenos hematomas temporários (resolvem naturalmente)
• Vermelhidão local passageira (24-48h)
• Raramente: reação alérgica local leve
• Risco mínimo de infeção (material 100% estéril e descartável)
• Possível sensação de formigueiro (resposta terapêutica)
• Ligeiro inchaço local (desaparece em horas)

CONTRAINDICAÇÕES E PRECAUÇÕES:
• Alergia conhecida aos componentes específicos
• Infeções locais ativas ou feridas abertas
• Distúrbios graves de coagulação diagnosticados
• Tratamento anticoagulante agressivo (informar médico)
• Gravidez - especialmente primeiro trimestre (consultar)
• Cicatrizes queloides ou problemas cicatriciais graves
• Sensibilidade extrema da pele ou reações dermatológicas

RESPONSABILIDADES DO PACIENTE - INFORMAÇÕES CRÍTICAS:
• Informar COMPLETAMENTE sobre todas as alergias
• Comunicar medicação atual, especialmente anticoagulantes
• Avisar imediatamente sobre gravidez
• Informar sobre distúrbios de coagulação
• Manter higiene local adequada pós-tratamento
• Evitar manipular ou tocar na área por 6-8 horas
• Não aplicar cremes ou produtos sem indicação
• Evitar exposição solar intensa (48h após)
• Reportar qualquer reação adversa inesperada

DURAÇÃO E FREQUÊNCIA:
• Sessão: 15-30 minutos (rápida e eficaz)
• Tratamentos: 1-2 vezes por semana
• Duração total: 4-10 sessões conforme protocolo
• Reavaliação: após 5 sessões
• Manutenção: mensal conforme necessidade
• Resultados: visíveis após 3-5 sessões"
            });



            _templates.Add("rgpd", new ConsentimentoTemplate
            {
                Titulo = "🔐 CONSENTIMENTO RGPD - PROTEÇÃO DE DADOS PESSOAIS",
                Texto = @"TRATAMENTO DE DADOS PESSOAIS - RGPD

RESPONSÁVEL PELO TRATAMENTO:
[Nome do Profissional/Clínica]
[Morada completa]
[Contactos]

FINALIDADE DO TRATAMENTO:
• Prestação de cuidados de saúde
• Gestão de consultas e tratamentos
• Comunicação com o paciente
• Faturação e arquivo clínico
• Cumprimento de obrigações legais

DADOS RECOLHIDOS:
• Dados de identificação
• Dados de contacto
• Dados de saúde (histórico clínico)
• Dados de tratamentos realizados
• Fotografias/imagens (se aplicável)

BASE LEGAL:
• Consentimento explícito do titular
• Interesse legítimo para prestação de cuidados
• Cumprimento de obrigação legal
• Proteção de interesses vitais

DESTINATÁRIOS:
• Profissionais de saúde envolvidos
• Entidades seguradoras (se aplicável)
• Autoridades de saúde (se obrigatório)
• Não há transferências para países terceiros

PRAZO DE CONSERVAÇÃO:
• Dados clínicos: 5 anos após última consulta
• Dados administrativos: conforme legislação
• Imagens/fotografias: com consentimento específico

DIREITOS DO TITULAR:
• Acesso aos seus dados
• Retificação de dados incorretos
• Apagamento (direito ao esquecimento)
• Limitação do tratamento
• Portabilidade dos dados
• Oposição ao tratamento
• Retirar consentimento a qualquer momento

CONTACTOS:
Para exercer os seus direitos ou esclarecimentos:
[Contacto do responsável pela proteção de dados]

AUTORIDADE DE CONTROLO:
Comissão Nacional de Proteção de Dados (CNPD)
www.cnpd.pt"
            });
        }

        private void TipoTratamentoCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (TipoTratamentoCombo.SelectedItem is ComboBoxItem item && item.Tag is string tag)
            {
                if (_templates.TryGetValue(tag, out var template))
                {
                    ConsentimentoTitle.Text = template.Titulo;
                    ConsentimentoTexto.Text = template.Texto;

                    // ✅ ACTUALIZAR O VIEWMODEL TAMBÉM!
                    if (DataContext is ConsentimentosViewModel viewModel)
                    {
                        viewModel.DescricaoTratamento = template.Texto;
                    }

                    ConsentimentoDeclaracoes.Visibility = Visibility.Visible;
                    BtnAssinar.Visibility = Visibility.Visible;
                }
            }
            else
            {
                ConsentimentoTitle.Text = "Selecione uma técnica para visualizar o consentimento informado";
                ConsentimentoTexto.Text = "Por favor, selecione uma técnica no menu acima para visualizar o respectivo consentimento informado.";

                // ✅ LIMPAR O VIEWMODEL TAMBÉM!
                if (DataContext is ConsentimentosViewModel viewModel)
                {
                    viewModel.DescricaoTratamento = string.Empty;
                }

                ConsentimentoDeclaracoes.Visibility = Visibility.Collapsed;
                BtnAssinar.Visibility = Visibility.Collapsed;
            }
        }

        private void BtnAssinar_Click(object sender, RoutedEventArgs e)
        {
            // Verificar se todas as declarações estão marcadas
            if (ChkCompreendi.IsChecked == true && ChkAceito.IsChecked == true && ChkConsinto.IsChecked == true)
            {
                if (!string.IsNullOrWhiteSpace(TxtNomePaciente.Text))
                {
                    // Mostrar seção de assinatura
                    AssinaturaSection.Visibility = Visibility.Visible;
                    BtnAssinar.Visibility = Visibility.Collapsed;

                    // Scroll para a assinatura
                    AssinaturaSection.BringIntoView();
                }
                else
                {
                    MessageBox.Show("Por favor, preencha o nome do paciente.", "Campo Obrigatório", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            else
            {
                MessageBox.Show("Por favor, confirme todas as declarações de consentimento.", "Consentimento Incompleto", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        // === COMANDOS VER E PDF ===

        private void BtnVer_Click(object sender, RoutedEventArgs e)
        {
            var btn = sender as Button;
            var consentimento = btn?.Tag as string;

            if (!string.IsNullOrEmpty(consentimento))
            {
                MessageBox.Show($"📄 Visualizando consentimento: {consentimento}\n\nEsta funcionalidade abrirá o documento completo em uma nova janela.",
                    "Ver Consentimento", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void BtnPDF_Click(object sender, RoutedEventArgs e)
        {
            // Chamar comando do ViewModel para gerar PDF
            var viewModel = DataContext as ViewModels.Abas.ConsentimentosViewModel;

            if (viewModel == null) return;

            // Gerar PDF (modifica viewModel.UltimoPdfGerado)
            viewModel.GerarPdfConsentimentoCommand.Execute(null);

            // Verificar resultado
            if (viewModel.UltimoPdfGerado == null)
            {
                MessageBox.Show(
                    "⚠️ Não foi possível gerar o PDF. Verifique:\n\n" +
                    "✓ Nome do paciente está preenchido\n" +
                    "✓ Tipo de tratamento selecionado\n" +
                    "✓ Descrição do tratamento preenchida",
                    "Dados Incompletos",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            // Perguntar se deseja abrir
            var resultado = MessageBox.Show(
                $"✅ PDF de consentimento gerado com sucesso!\n\n📁 Local: {viewModel.UltimoPdfGerado}\n\nDeseja abrir o documento agora?",
                "PDF Gerado",
                MessageBoxButton.YesNo,
                MessageBoxImage.Information);

            if (resultado == MessageBoxResult.Yes)
            {
                viewModel.AbrirPdf(viewModel.UltimoPdfGerado);
            }
        }

        // === SISTEMA DE ASSINATURA DIGITAL ===

        private void AssinaturaCanvas_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed)
            {
                _isDrawing = true;
                AssinaturaInstrucoes.Visibility = Visibility.Collapsed;
                AssinaturaCanvas.CaptureMouse();

                // Iniciar novo traço
                _currentStroke = new Polyline
                {
                    Stroke = new SolidColorBrush(Color.FromRgb(63, 74, 61)), // #3F4A3D
                    StrokeThickness = 2.5,
                    StrokeLineJoin = PenLineJoin.Round
                };

                Point startPoint = e.GetPosition(AssinaturaCanvas);
                _currentStroke.Points.Add(startPoint);
                AssinaturaCanvas.Children.Add(_currentStroke);
            }
        }

        private void AssinaturaCanvas_MouseMove(object sender, MouseEventArgs e)
        {
            if (_isDrawing && e.LeftButton == MouseButtonState.Pressed && _currentStroke != null)
            {
                Point currentPoint = e.GetPosition(AssinaturaCanvas);
                _currentStroke.Points.Add(currentPoint);

                if (!_hasSignature)
                {
                    _hasSignature = true;
                    BtnConfirmarAssinatura.IsEnabled = true;
                }
            }
        }

        private void AssinaturaCanvas_MouseUp(object sender, MouseButtonEventArgs e)
        {
            _isDrawing = false;
            AssinaturaCanvas.ReleaseMouseCapture();
            _currentStroke = null;
        }

        private void BtnLimparAssinatura_Click(object sender, RoutedEventArgs e)
        {
            AssinaturaCanvas.Children.Clear();
            AssinaturaInstrucoes.Visibility = Visibility.Visible;
            _hasSignature = false;
            BtnConfirmarAssinatura.IsEnabled = false;
            _currentStroke = null;
        }

        /// <summary>
        /// Captura a assinatura do canvas e converte para Base64 (PNG)
        /// </summary>
        private string CapturarAssinaturaComoImagem()
        {
            try
            {
                // Verificar se canvas tem tamanho válido
                if (AssinaturaCanvas.ActualWidth <= 0 || AssinaturaCanvas.ActualHeight <= 0)
                {
                    return string.Empty;
                }

                // Criar bitmap com resolução do canvas
                var renderBitmap = new RenderTargetBitmap(
                    (int)AssinaturaCanvas.ActualWidth,
                    (int)AssinaturaCanvas.ActualHeight,
                    96, // DPI horizontal
                    96, // DPI vertical
                    PixelFormats.Pbgra32);

                // Renderizar canvas no bitmap
                renderBitmap.Render(AssinaturaCanvas);

                // Codificar como PNG
                var encoder = new PngBitmapEncoder();
                encoder.Frames.Add(BitmapFrame.Create(renderBitmap));

                // Converter para Base64
                using (var memoryStream = new MemoryStream())
                {
                    encoder.Save(memoryStream);
                    byte[] imageBytes = memoryStream.ToArray();
                    string base64String = Convert.ToBase64String(imageBytes);
                    return base64String;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"❌ Erro ao capturar assinatura como imagem:\n\n{ex.Message}",
                    "Erro de Captura",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                return string.Empty;
            }
        }

        private void BtnConfirmarAssinatura_Click(object sender, RoutedEventArgs e)
        {
            if (_hasSignature)
            {
                // ✅ GUARDAR DADOS ANTES DO RESET
                var viewModel = DataContext as ConsentimentosViewModel;
                if (viewModel != null)
                {
                    // 🖼️ CAPTURAR ASSINATURA COMO IMAGEM BASE64
                    string assinaturaBase64 = CapturarAssinaturaComoImagem();
                    viewModel.AssinaturaDigitalBase64 = assinaturaBase64;

                    // Invocar assinatura digital no ViewModel
                    viewModel.AssinarDigitalmenteCommand.Execute(null);

                    MessageBox.Show(
                        $"✅ Consentimento assinado digitalmente com sucesso!\n\n" +
                        $"Paciente: {viewModel.NomePaciente}\n" +
                        $"Data: {DateTime.Now:dd/MM/yyyy HH:mm}\n" +
                        $"Técnica: {viewModel.TipoTratamentoSelecionado}\n\n" +
                        $"Clique no botão 'Gerar PDF' abaixo para criar o documento.",
                        "✅ Assinatura Confirmada",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }
                else
                {
                    MessageBox.Show(
                        "✅ Consentimento assinado digitalmente com sucesso!\n\nClique no botão 'Gerar PDF' abaixo.",
                        "✅ Assinatura Confirmada",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }

                // ✅ LIMPAR APENAS O CANVAS DE ASSINATURA (não o formulário!)
                AssinaturaCanvas.Children.Clear();
                AssinaturaInstrucoes.Visibility = Visibility.Visible;
                AssinaturaSection.Visibility = Visibility.Collapsed;
                _hasSignature = false;
                BtnConfirmarAssinatura.IsEnabled = false;
                _currentStroke = null;

                // ✅ MOSTRAR BOTÃO DE GERAR PDF!
                BtnGerarPdfNovo.Visibility = Visibility.Visible;

                // ❌ NÃO LIMPAR O FORMULÁRIO! Os dados são necessários para o PDF!
            }
            else
            {
                MessageBox.Show("Por favor, assine no campo acima antes de confirmar.", "Assinatura Necessária", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        private void BtnGerarPdfNovo_Click(object sender, RoutedEventArgs e)
        {
            var viewModel = DataContext as ConsentimentosViewModel;
            if (viewModel == null) return;

            // ⚠️ WORKAROUND: Source Generator não funciona - usar Reflection como em RegistoConsultasUserControl
            try
            {
                var method = viewModel.GetType().GetMethod("GerarPdfConsentimento", BindingFlags.NonPublic | BindingFlags.Instance);
                if (method != null)
                {
                    method.Invoke(viewModel, null);
                }
                else
                {
                    MessageBox.Show("❌ ERRO: Método GerarPdfConsentimento não encontrado via Reflection!", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"❌ ERRO na Reflection: {ex.Message}\n\nInner: {ex.InnerException?.Message}", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            // Se sucesso, perguntar se deseja abrir
            if (!string.IsNullOrEmpty(viewModel.UltimoPdfGerado))
            {
                var resultado = MessageBox.Show(
                    $"✅ PDF de consentimento gerado com sucesso!\n\n📁 Local: {viewModel.UltimoPdfGerado}\n\nDeseja abrir o documento agora?",
                    "PDF Gerado",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Information);

                if (resultado == MessageBoxResult.Yes)
                {
                    try
                    {
                        Process.Start(new ProcessStartInfo
                        {
                            FileName = viewModel.UltimoPdfGerado,
                            UseShellExecute = true
                        });
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show(
                            $"❌ Erro ao abrir PDF: {ex.Message}",
                            "Erro",
                            MessageBoxButton.OK,
                            MessageBoxImage.Error);
                    }
                }
            }
            // Se falhou, ViewModel já mostrou mensagem específica - NÃO mostrar mensagem genérica
        }
        public class ConsentimentoTemplate
        {
            public string Titulo { get; set; } = string.Empty;
            public string Texto { get; set; } = string.Empty;
        }
    }
}
