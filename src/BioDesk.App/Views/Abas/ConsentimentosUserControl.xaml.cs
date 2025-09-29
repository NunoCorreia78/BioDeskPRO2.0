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
            _templates = new Dictionary<string, ConsentimentoTemplate>();
            InicializarTemplates();
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

            _templates.Add("fitoterapia", new ConsentimentoTemplate
            {
                Titulo = "🌱 CONSENTIMENTO INFORMADO - FITOTERAPIA",
                Texto = @"NATUREZA DO TRATAMENTO:
A Fitoterapia utiliza plantas medicinais e seus extratos para prevenir e tratar diversos desequilíbrios de saúde de forma natural.

BENEFÍCIOS ESPERADOS:
• Tratamento natural de sintomas
• Fortalecimento de órgãos e sistemas
• Melhoria da vitalidade
• Equilíbrio funcional do organismo
• Complemento ao tratamento convencional

RISCOS E PRECAUÇÕES:
• Possíveis reações alérgicas
• Interações com medicamentos
• Efeitos secundários específicos de cada planta
• Dosagem inadequada pode ser ineficaz ou prejudicial

RESPONSABILIDADES DO PACIENTE:
• Informar toda a medicação atual
• Comunicar alergias conhecidas
• Seguir dosagens prescritas rigorosamente
• Informar sobre gravidez/amamentação
• Comunicar qualquer reação adversa"
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
            var btn = sender as Button;
            var consentimento = btn?.Tag as string;

            if (!string.IsNullOrEmpty(consentimento))
            {
                MessageBox.Show($"📑 Gerando PDF: {consentimento}\n\nO documento será salvo em:\nDocumentos/BioDeskPro2/Consentimentos/\n\nFuncionalidade será implementada na próxima versão.",
                    "Gerar PDF", MessageBoxButton.OK, MessageBoxImage.Information);
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
                MessageBox.Show($"Consentimento assinado digitalmente com sucesso!\n\nPaciente: {TxtNomePaciente.Text}\nData: {DateConsentimento.SelectedDate:dd/MM/yyyy}\nTécnica: {((ComboBoxItem)TipoTratamentoCombo.SelectedItem)?.Content}",
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
