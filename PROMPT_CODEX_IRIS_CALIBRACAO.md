# PROMPT PARA CODEX GPT - CORREÇÃO SISTEMA CALIBRAÇÃO ÍRIS

## CONTEXTO DO PROBLEMA

Tenho uma aplicação WPF em C# .NET 8 com um sistema de calibração de íris que apresenta 3 problemas críticos:

1. **Deteção automática não funciona** - O botão "Detectar Limites Automaticamente" não faz nada visível
2. **Marcações visuais não aparecem** - Os pontos de calibração não são visíveis no canvas, exceto num canto específico
3. **Zonas do canvas não aceitam cliques** - Especialmente a extremidade direita do canvas não responde

## ARQUITETURA ATUAL

### XAML - Canvas System (1400x1400 pixels)
```xml
<!-- Container principal -->
<Viewbox Stretch="Uniform" HorizontalAlignment="Center" VerticalAlignment="Center">
    <Canvas x:Name="MainCanvas" Width="1400" Height="1400">

        <!-- Imagem de fundo da íris -->
        <Image x:Name="IrisCentralImage"
               Source="{Binding ImagemIris}"
               Width="1400" Height="1400"
               Canvas.Left="0" Canvas.Top="0"/>

        <!-- Canvas para marcações visuais -->
        <Canvas x:Name="MarkingsCanvas"
                Width="1400" Height="1400"
                Panel.ZIndex="300"
                Background="Transparent"
                MouseLeftButtonDown="{Binding CanvasClickCommand}">

            <!-- Pontos visuais de calibração -->
            <ItemsControl ItemsSource="{Binding PontosVisuais}">
                <ItemsControl.ItemsPanel>
                    <ItemsPanelTemplate><Canvas/></ItemsPanelTemplate>
                </ItemsControl.ItemsPanel>
                <ItemsControl.ItemContainerStyle>
                    <Style TargetType="ContentPresenter">
                        <Setter Property="Canvas.Left">
                            <Setter.Value>
                                <Binding Path="X" StringFormat="{}{0}"/>
                            </Setter.Value>
                        </Setter>
                        <Setter Property="Canvas.Top">
                            <Setter.Value>
                                <Binding Path="Y" StringFormat="{}{0}"/>
                            </Setter.Value>
                        </Setter>
                    </Style>
                </ItemsControl.ItemContainerStyle>
                <ItemsControl.ItemTemplate>
                    <DataTemplate>
                        <Ellipse Width="32" Height="32"
                                Fill="{Binding Cor}"
                                Stroke="Black" StrokeThickness="2"/>
                    </DataTemplate>
                </ItemsControl.ItemTemplate>
            </ItemsControl>

            <!-- Feedback de cliques temporários -->
            <ItemsControl ItemsSource="{Binding ClicksTemporarios}">
                <!-- Estrutura similar aos PontosVisuais -->
            </ItemsControl>
        </Canvas>
    </Canvas>
</Viewbox>
```

### ViewModel - Coordenadas e Lógica
```csharp
public partial class IrisdiagnosticoViewModel : NavigationViewModelBase
{
    // Constantes de calibração (já corrigidas para 1400x1400)
    private const double RAIO_NOMINAL_PUPILA = 120.0;
    private const double RAIO_NOMINAL_IRIS = 320.0;

    // Centro do canvas 1400x1400
    [ObservableProperty] private double _centroPupilaX = 700.0;
    [ObservableProperty] private double _centroPupilaY = 700.0;
    [ObservableProperty] private double _centroIrisX = 700.0;
    [ObservableProperty] private double _centroIrisY = 700.0;

    // Coleções para visualização
    [ObservableProperty] private ObservableCollection<PontoVisual> _pontosVisuais = new();
    [ObservableProperty] private ObservableCollection<ClickTemporario> _clicksTemporarios = new();

    // PROBLEMA: Este comando não produz resultados visuais
    [RelayCommand]
    private async Task DetectarLimitesAutomaticamenteAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            DetectarPupilaAutomaticamente();
            DetectarIrisAutomaticamente();
        });
    }

    // PROBLEMA: Estes métodos adicionam pontos mas não aparecem visualmente
    private void DetectarPupilaAutomaticamente()
    {
        var pontos = GerarPontosCardeais(CentroPupilaX, CentroPupilaY, RaioPupila);

        foreach (var ponto in pontos)
        {
            PontosVisuais.Add(new PontoVisual
            {
                X = ponto.X - 16, // Centrar elemento 32px
                Y = ponto.Y - 16,
                Cor = new SolidColorBrush(Colors.Red),
                Tipo = TipoPonto.Pupila
            });
        }
    }

    // PROBLEMA: Cliques só funcionam em certas zonas do canvas
    [RelayCommand]
    private void CanvasClick(MouseButtonEventArgs e)
    {
        var canvas = e.Source as Canvas;
        var position = e.GetPosition(canvas);

        // Debug logging
        Debug.WriteLine($"Canvas click: X={position.X}, Y={position.Y}");

        MostrarFeedbackClique(position.X, position.Y);
    }

    private void MostrarFeedbackClique(double x, double y)
    {
        ClicksTemporarios.Add(new ClickTemporario
        {
            X = x - 12, // Centrar elemento 24px
            Y = y - 12,
            Cor = new SolidColorBrush(Colors.Yellow)
        });

        // Remove após 2 segundos
        Task.Delay(2000).ContinueWith(_ => Application.Current.Dispatcher.Invoke(() =>
        {
            if (ClicksTemporarios.Count > 0)
                ClicksTemporarios.RemoveAt(0);
        }));
    }
}
```

### Classes de Dados
```csharp
public class PontoVisual
{
    public double X { get; set; }
    public double Y { get; set; }
    public SolidColorBrush Cor { get; set; } = new(Colors.Red);
    public TipoPonto Tipo { get; set; }
}

public class ClickTemporario
{
    public double X { get; set; }
    public double Y { get; set; }
    public SolidColorBrush Cor { get; set; } = new(Colors.Yellow);
}

public enum TipoPonto { Pupila, Iris }
```

## COMPORTAMENTO OBSERVADO VS ESPERADO

### 🔴 PROBLEMA 1 - Deteção Automática
- **Atual**: Comando executa sem erros mas não aparecem pontos visuais
- **Esperado**: 8 pontos vermelhos na orla da pupila + 8 pontos azuis na orla da íris

### 🔴 PROBLEMA 2 - Visualização de Pontos
- **Atual**: PontosVisuais collection é populada mas elementos não renderizam no canvas
- **Esperado**: Círculos coloridos de 32px visíveis nas coordenadas calculadas

### 🔴 PROBLEMA 3 - Interação Canvas
- **Atual**: Cliques só funcionam num canto, extremidade direita não responde
- **Esperado**: Todo o canvas 1400x1400 deve aceitar cliques e mostrar feedback amarelo

## EVIDÊNCIA VISUAL DO PROBLEMA

O utilizador demonstrou manualmente como os pontos DEVERIAM aparecer - pontos amarelos bem visíveis na orla da pupila e íris. Atualmente, os pontos só aparecem incorretamente num canto específico.

## MÉTODOS AUXILIARES RELEVANTES

```csharp
private List<Point> GerarPontosCardeais(double centroX, double centroY, double raio)
{
    var pontos = new List<Point>();
    for (int i = 0; i < 8; i++)
    {
        double angulo = i * Math.PI / 4; // 45° increments
        double x = centroX + raio * Math.Cos(angulo);
        double y = centroY + raio * Math.Sin(angulo);
        pontos.Add(new Point(x, y));
    }
    return pontos;
}
```

## O QUE PRECISO

1. **Corrigir a visualização dos pontos** - Os PontoVisual objects devem renderizar corretamente no canvas
2. **Fazer a deteção automática funcionar** - Os 16 pontos (8 pupila + 8 íris) devem aparecer quando o comando é executado
3. **Corrigir as zonas mortas do canvas** - Todo o canvas deve aceitar cliques e mostrar feedback

## SUSPEITAS TÉCNICAS

- Possível problema com coordinate system no Viewbox com Stretch="Uniform"
- ItemsControl binding pode ter problemas com Canvas positioning
- Event handling pode estar sendo bloqueado por z-index ou transparência
- Conversão de coordenadas entre diferentes sistemas (mouse position vs canvas coordinates)

## OBJETIVO FINAL

Sistema de calibração totalmente funcional onde:
- Botão "Detectar Automaticamente" mostra 16 pontos coloridos nas orlas
- Utilizador pode clicar em qualquer zona do canvas para calibração manual
- Feedback visual imediato e preciso em todas as interações

**Formato de resposta desejado**: Código WPF/C# corrigido com explicação das mudanças fundamentais necessárias para resolver os 3 problemas.
