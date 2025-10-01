using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;

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
A Naturopatia é uma medicina natural que visa estimular os mecanismos de autocura do organismo através de métodos naturais, incluindo fitoterapia, nutrição, hidroterapia e outras terapias complementares.

BENEFÍCIOS ESPERADOS:
• Melhoria do bem-estar geral
• Fortalecimento do sistema imunitário
• Redução de sintomas crónicos
• Melhoria da qualidade de vida
• Equilíbrio energético do organismo

RISCOS E LIMITAÇÕES:
• Reações alérgicas a produtos naturais (raras)
• Interações com medicamentos convencionais
• Tempo de resposta variável entre indivíduos
• Não substitui tratamento médico convencional em situações agudas

CONTRAINDICAÇÕES:
• Gravidez e amamentação (alguns produtos)
• Alergias conhecidas a plantas específicas
• Doenças graves em fase aguda
• Uso concomitante de anticoagulantes (alguns produtos)

RESPONSABILIDADES DO PACIENTE:
• Informar sobre medicação atual
• Comunicar alergias conhecidas
• Seguir as recomendações do naturopata
• Informar sobre gravidez ou suspeita
• Manter seguimento médico convencional se necessário"
            });

            _templates.Add("osteopatia", new ConsentimentoTemplate
            {
                Titulo = "🦴 CONSENTIMENTO INFORMADO - OSTEOPATIA",
                Texto = @"NATUREZA DO TRATAMENTO:
A Osteopatia é uma terapia manual que visa restabelecer o equilíbrio do corpo através de técnicas específicas de mobilização, manipulação articular e tecidos moles.

BENEFÍCIOS ESPERADOS:
• Alívio de dores musculoesqueléticas
• Melhoria da mobilidade articular
• Redução de tensões musculares
• Melhoria da postura
• Alívio de cefaleias tensionais

RISCOS POTENCIAIS:
• Dor temporária após o tratamento (normal)
• Rigidez temporária (24-48h)
• Raramente: agravamento temporário dos sintomas
• Muito raramente: lesão vascular ou nervosa

CONTRAINDICAÇÕES ABSOLUTAS:
• Fraturas recentes
• Infeções agudas
• Tumores na área a tratar
• Osteoporose severa
• Artrite reumatoide em fase aguda

RESPONSABILIDADES DO PACIENTE:
• Informar sobre medicação e condições médicas
• Comunicar dor ou desconforto durante o tratamento
• Seguir exercícios recomendados
• Informar sobre gravidez
• Comunicar qualquer reação adversa"
            });

            _templates.Add("acupunctura", new ConsentimentoTemplate
            {
                Titulo = "🪡 CONSENTIMENTO INFORMADO - ACUPUNCTURA",
                Texto = @"NATUREZA DO TRATAMENTO:
A Acupunctura é uma técnica da Medicina Tradicional Chinesa que utiliza agulhas estéreis inseridas em pontos específicos do corpo para equilibrar a energia vital (Qi).

BENEFÍCIOS ESPERADOS:
• Alívio da dor crónica
• Redução de stress e ansiedade
• Melhoria da qualidade do sono
• Regulação de funções orgânicas
• Fortalecimento do sistema imunitário

RISCOS E EFEITOS SECUNDÁRIOS:
• Dor ligeira na inserção das agulhas
• Pequenos hematomas nos pontos de inserção
• Raramente: infeção local
• Muito raramente: pneumotórax (punção torácica)
• Possível sonolência após a sessão

CONTRAINDICAÇÕES:
• Distúrbios de coagulação
• Uso de anticoagulantes
• Gravidez (alguns pontos)
• Infeções cutâneas na área a tratar
• Estados febris agudos

RESPONSABILIDADES DO PACIENTE:
• Informar sobre medicação anticoagulante
• Comunicar gravidez ou suspeita
• Avisar sobre medo de agulhas
• Informar sobre alergias ao álcool/iodo
• Comunicar qualquer reação adversa"
            });

            _templates.Add("massagem", new ConsentimentoTemplate
            {
                Titulo = "💆 CONSENTIMENTO INFORMADO - MASSAGEM TERAPÊUTICA",
                Texto = @"NATUREZA DO TRATAMENTO:
A Massagem Terapêutica utiliza técnicas manuais específicas para tratar tensões musculares, melhorar a circulação e promover o relaxamento.

BENEFÍCIOS ESPERADOS:
• Alívio de tensões musculares
• Melhoria da circulação sanguínea
• Redução do stress
• Relaxamento geral
• Melhoria da qualidade do sono

RISCOS MÍNIMOS:
• Dor ligeira durante ou após a massagem
• Hematomas ligeiros (raros)
• Reações cutâneas a óleos (raras)
• Tonturas ligeiras após a sessão

RESPONSABILIDADES DO PACIENTE:
• Informar sobre condições médicas
• Comunicar alergias a produtos
• Avisar sobre gravidez
• Indicar áreas sensíveis ou dolorosas
• Comunicar desconforto durante o tratamento"
            });

            _templates.Add("bioenergetica", new ConsentimentoTemplate
            {
                Titulo = "🧘 CONSENTIMENTO INFORMADO - TERAPIA BIOENERGÉTICA",
                Texto = @"NATUREZA DO TRATAMENTO:
A Terapia Bioenergética trabalha com o campo energético do organismo através de técnicas de harmonização e equilíbrio da energia vital.

BENEFÍCIOS ESPERADOS:
• Equilíbrio energético geral
• Redução do stress
• Melhoria do bem-estar emocional
• Harmonização de chakras
• Aumento da vitalidade

LIMITAÇÕES:
• Resultados variam entre indivíduos
• Não é diagnóstico médico
• Não substitui medicação prescrita
• Abordagem complementar

RESPONSABILIDADES DO PACIENTE:
• Manter tratamento médico convencional
• Comunicar condições psiquiátricas
• Ter expectativas realistas
• Comunicar qualquer desconforto emocional"
            });

            // ===== NOVAS TÉCNICAS ESPECIALIZADAS =====

            _templates.Add("iridologia", new ConsentimentoTemplate
            {
                Titulo = "👁️ CONSENTIMENTO INFORMADO - IRIDOLOGIA",
                Texto = @"NATUREZA DO EXAME:
A Iridologia é uma técnica de análise da íris ocular para avaliação da condição geral de saúde e identificação de predisposições constitucionais.

PROCEDIMENTO:
• Observação detalhada da íris com lupa especializada
• Possível fotografia da íris (com consentimento)
• Análise de padrões, cores e marcas
• Correlação com mapa iridológico
• Elaboração de relatório informativo

LIMITAÇÕES IMPORTANTES:
• NÃO é diagnóstico médico
• NÃO substitui exames clínicos
• Indica tendências constitucionais
• Ferramenta de avaliação complementar
• Não detecta doenças específicas

RESPONSABILIDADES DO PACIENTE:
• Manter seguimento médico regular
• Não interromper medicação prescrita
• Usar informações como orientação preventiva
• Procurar médico para sintomas específicos

PROTEÇÃO DE DADOS:
• Imagens armazenadas com segurança
• Uso exclusivo para análise iridológica
• Não partilha com terceiros"
            });

            _templates.Add("mesoterapia", new ConsentimentoTemplate
            {
                Titulo = "💉 CONSENTIMENTO INFORMADO - MESOTERAPIA HOMEOPÁTICA",
                Texto = @"NATUREZA DO TRATAMENTO:
A Mesoterapia Homeopática consiste na aplicação de medicamentos homeopáticos através de micro-injeções dérmicas superficiais em pontos específicos.

PROCEDIMENTO:
• Preparação e desinfeção da área
• Aplicação de agulhas muito finas (4-6mm)
• Injeção de preparados homeopáticos
• Possível aplicação de compressas locais
• Observação pós-aplicação

BENEFÍCIOS ESPERADOS:
• Ação localizada do medicamento
• Estimulação de pontos específicos
• Melhoria da circulação local
• Redução de inflamação
• Harmonização energética local

RISCOS POTENCIAIS:
• Dor leve no local da aplicação
• Pequenos hematomas temporários
• Vermelhidão local (24-48h)
• Raramente: reação alérgica local
• Risco mínimo de infeção (material estéril)

CONTRAINDICAÇÕES:
• Alergia conhecida aos componentes
• Infeções locais ativas
• Distúrbios de coagulação graves
• Tratamento anticoagulante (consultar médico)
• Gravidez (primeiro trimestre)

RESPONSABILIDADES DO PACIENTE:
• Informar alergias e medicação
• Comunicar distúrbios de coagulação
• Manter higiene local pós-tratamento
• Evitar manipular área tratada nas primeiras 6h"
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
                    ConsentimentoDeclaracoes.Visibility = Visibility.Visible;
                    BtnAssinar.Visibility = Visibility.Visible;
                }
            }
            else
            {
                ConsentimentoTitle.Text = "Selecione uma técnica para visualizar o consentimento informado";
                ConsentimentoTexto.Text = "Por favor, selecione uma técnica no menu acima para visualizar o respectivo consentimento informado.";
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

        private void BtnConfirmarAssinatura_Click(object sender, RoutedEventArgs e)
        {
            if (_hasSignature)
            {
                MessageBox.Show($"Consentimento assinado digitalmente com sucesso!\n\nPaciente: {TxtNomePaciente.Text}\nData: {TxtDataConsentimento.Text}\nTécnica: {((ComboBoxItem)TipoTratamentoCombo.SelectedItem)?.Content}",
                    "✅ Assinatura Confirmada", MessageBoxButton.OK, MessageBoxImage.Information);

                // Reset do formulário
                TipoTratamentoCombo.SelectedIndex = 0;
                ChkCompreendi.IsChecked = false;
                ChkAceito.IsChecked = false;
                ChkConsinto.IsChecked = false;
                TxtNomePaciente.Clear();
                AssinaturaCanvas.Children.Clear();
                AssinaturaInstrucoes.Visibility = Visibility.Visible;
                AssinaturaSection.Visibility = Visibility.Collapsed;
                BtnAssinar.Visibility = Visibility.Collapsed;
                _hasSignature = false;
                BtnConfirmarAssinatura.IsEnabled = false;
                _currentStroke = null;
            }
            else
            {
                MessageBox.Show("Por favor, assine no campo acima antes de confirmar.", "Assinatura Necessária", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
        public class ConsentimentoTemplate
        {
            public string Titulo { get; set; } = string.Empty;
            public string Texto { get; set; } = string.Empty;
        }
    }
}
