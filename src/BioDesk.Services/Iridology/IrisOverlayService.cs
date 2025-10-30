using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Media;

namespace BioDesk.Services.Iridology
{
    public class IrisOverlayService : INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler? PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        public enum AlignmentPhase
        {
            Idle,
            ClickCenterPupil,
            ClickRightPupil,
            ClickTopPupil,
            ClickRightIris,
            ClickTopIris,
            Calculating,
            ManualAdjust,
            Completed
        }

        private AlignmentPhase _currentPhase = AlignmentPhase.Idle;
        private Point _centroPupila;
        private Point _bordaDireitaPupila;
        private Point _bordaTopoPupila;
        private Point _bordaDireitaIris;
        private Point _bordaTopoIris;

        private const double MAPA_ORIGINAL_SIZE = 800;

        private double _scaleX = 1.0;
        private double _scaleY = 1.0;
        private double _translateX = 0.0;
        private double _translateY = 0.0;
        private double _rotation = 0.0;

        // 🎯 DADOS POLARES CALIBRADOS AVANÇADOS (para uso no rendering)
        private double _raioPupilaH = 0.0;  // Raio horizontal pupila
        private double _raioPupilaV = 0.0;  // Raio vertical pupila
        private double _raioIrisH = 0.0;    // Raio horizontal íris
        private double _raioIrisV = 0.0;    // Raio vertical íris
        private Point _centroPupilaCalibrado = new Point(0, 0);
        private Point _centroIrisCalibrado = new Point(0, 0);
        private double _rotacaoCalibrada = 0.0;

        // 📐 ESCALAS POR QUADRANTE (para íris assimétricas/cortadas)
        private double _escalaQuadrante1 = 1.0; // 0-90°
        private double _escalaQuadrante2 = 1.0; // 90-180°
        private double _escalaQuadrante3 = 1.0; // 180-270°
        private double _escalaQuadrante4 = 1.0; // 270-360°

        public event EventHandler<AlignmentPhase>? PhaseChanged;
        public event EventHandler<TransformGroup>? TransformCalculated;
        public event EventHandler<string>? StatusMessageChanged;

        public AlignmentPhase CurrentPhase
        {
            get => _currentPhase;
            private set
            {
                if (_currentPhase != value)
                {
                    _currentPhase = value;
                    PhaseChanged?.Invoke(this, value);
                    UpdateStatusMessage();
                }
            }
        }

        public double ScaleX
        {
            get => _scaleX;
            set
            {
                if (_scaleX != value)
                {
                    _scaleX = value;
                    OnPropertyChanged();
                    RecalculateTransform();
                }
            }
        }

        public double ScaleY
        {
            get => _scaleY;
            set
            {
                if (_scaleY != value)
                {
                    _scaleY = value;
                    OnPropertyChanged();
                    RecalculateTransform();
                }
            }
        }

        public double TranslateX
        {
            get => _translateX;
            set
            {
                if (_translateX != value)
                {
                    _translateX = value;
                    OnPropertyChanged();
                    RecalculateTransform();
                }
            }
        }

        public double TranslateY
        {
            get => _translateY;
            set
            {
                if (_translateY != value)
                {
                    _translateY = value;
                    OnPropertyChanged();
                    RecalculateTransform();
                }
            }
        }

        public double Rotation
        {
            get => _rotation;
            set
            {
                if (_rotation != value)
                {
                    _rotation = value;
                    OnPropertyChanged();
                    RecalculateTransform();
                }
            }
        }

        // 🎯 PROPRIEDADES POLARES PÚBLICAS (read-only para rendering)
        public double RaioPupilaH => _raioPupilaH;
        public double RaioPupilaV => _raioPupilaV;
        public double RaioIrisH => _raioIrisH;
        public double RaioIrisV => _raioIrisV;
        public Point CentroPupilaCalibrado => _centroPupilaCalibrado;
        public Point CentroIrisCalibrado => _centroIrisCalibrado;
        public double RotacaoCalibrada => _rotacaoCalibrada;

        // 📐 PROPRIEDADES DE ESCALA POR QUADRANTE (editáveis via sliders)
        private double _escalaQuadrante1Ajuste = 1.0;
        private double _escalaQuadrante2Ajuste = 1.0;
        private double _escalaQuadrante3Ajuste = 1.0;
        private double _escalaQuadrante4Ajuste = 1.0;

        public double EscalaQuadrante1
        {
            get => _escalaQuadrante1Ajuste;
            set
            {
                if (_escalaQuadrante1Ajuste != value)
                {
                    _escalaQuadrante1Ajuste = value;
                    OnPropertyChanged();
                    RecalculateTransform();
                }
            }
        }

        public double EscalaQuadrante2
        {
            get => _escalaQuadrante2Ajuste;
            set
            {
                if (_escalaQuadrante2Ajuste != value)
                {
                    _escalaQuadrante2Ajuste = value;
                    OnPropertyChanged();
                    RecalculateTransform();
                }
            }
        }

        public double EscalaQuadrante3
        {
            get => _escalaQuadrante3Ajuste;
            set
            {
                if (_escalaQuadrante3Ajuste != value)
                {
                    _escalaQuadrante3Ajuste = value;
                    OnPropertyChanged();
                    RecalculateTransform();
                }
            }
        }

        public double EscalaQuadrante4
        {
            get => _escalaQuadrante4Ajuste;
            set
            {
                if (_escalaQuadrante4Ajuste != value)
                {
                    _escalaQuadrante4Ajuste = value;
                    OnPropertyChanged();
                    RecalculateTransform();
                }
            }
        }

        /// <summary>
        /// Retorna a escala ajustada para um ângulo específico baseado nos quadrantes
        /// </summary>
        public double GetEscalaPorAngulo(double anguloGraus)
        {
            // Normalizar ângulo para 0-360
            while (anguloGraus < 0) anguloGraus += 360;
            while (anguloGraus >= 360) anguloGraus -= 360;

            if (anguloGraus < 90) return _escalaQuadrante1 * _escalaQuadrante1Ajuste;
            if (anguloGraus < 180) return _escalaQuadrante2 * _escalaQuadrante2Ajuste;
            if (anguloGraus < 270) return _escalaQuadrante3 * _escalaQuadrante3Ajuste;
            return _escalaQuadrante4 * _escalaQuadrante4Ajuste;
        }

        public void StartAlignment()
        {
            ResetAlignment();
            CurrentPhase = AlignmentPhase.ClickCenterPupil;
        }

        public bool ProcessClick(Point clickPoint)
        {
            switch (CurrentPhase)
            {
                case AlignmentPhase.ClickCenterPupil:
                    _centroPupila = clickPoint;
                    CurrentPhase = AlignmentPhase.ClickRightPupil;
                    return false; // Ainda não completou os 5 cliques

                case AlignmentPhase.ClickRightPupil:
                    _bordaDireitaPupila = clickPoint;
                    CurrentPhase = AlignmentPhase.ClickTopPupil;
                    return false; // Ainda não completou os 5 cliques

                case AlignmentPhase.ClickTopPupil:
                    _bordaTopoPupila = clickPoint;
                    CurrentPhase = AlignmentPhase.ClickRightIris;
                    return false; // Ainda não completou os 5 cliques

                case AlignmentPhase.ClickRightIris:
                    _bordaDireitaIris = clickPoint;
                    CurrentPhase = AlignmentPhase.ClickTopIris;
                    return false; // Ainda não completou os 5 cliques

                case AlignmentPhase.ClickTopIris:
                    _bordaTopoIris = clickPoint;
                    CurrentPhase = AlignmentPhase.Calculating;
                    CalculateEllipticalTransform();
                    CurrentPhase = AlignmentPhase.ManualAdjust;
                    return true; // ✅ TODOS os 5 cliques completos!

                default:
                    return false;
            }
        }

        private void CalculateEllipticalTransform()
        {
            try
            {
                double raioPupilaH = Math.Abs(_bordaDireitaPupila.X - _centroPupila.X);
                double raioPupilaV = Math.Abs(_bordaTopoPupila.Y - _centroPupila.Y);
                double raioIrisH = Math.Abs(_bordaDireitaIris.X - _centroPupila.X);
                double raioIrisV = Math.Abs(_bordaTopoIris.Y - _centroPupila.Y);

                if (raioPupilaH < 5 || raioPupilaV < 5 || raioIrisH < 10 || raioIrisV < 10)
                {
                    StatusMessageChanged?.Invoke(this, "Erro: Medidas muito pequenas.");
                    ResetAlignment();
                    return;
                }

                if (raioIrisH <= raioPupilaH || raioIrisV <= raioPupilaV)
                {
                    StatusMessageChanged?.Invoke(this, "Erro: Iris deve ser maior que pupila.");
                    ResetAlignment();
                    return;
                }

                // 🎯 ARMAZENAR DADOS POLARES INDEPENDENTES (H/V separados!)
                _raioPupilaH = raioPupilaH;
                _raioPupilaV = raioPupilaV;
                _raioIrisH = raioIrisH;
                _raioIrisV = raioIrisV;
                _centroPupilaCalibrado = _centroPupila;
                _centroIrisCalibrado = _centroPupila; // Inicialmente coincidente
                _rotacaoCalibrada = 0.0;

                // 📐 Resetar escalas por quadrante
                _escalaQuadrante1 = 1.0;
                _escalaQuadrante2 = 1.0;
                _escalaQuadrante3 = 1.0;
                _escalaQuadrante4 = 1.0;

                // Calcular escala para transformação WPF (compatibilidade com overlay visual)
                _scaleX = (raioIrisH * 2) / MAPA_ORIGINAL_SIZE;
                _scaleY = (raioIrisV * 2) / MAPA_ORIGINAL_SIZE;
                _translateX = _centroPupila.X - (MAPA_ORIGINAL_SIZE / 2 * _scaleX);
                _translateY = _centroPupila.Y - (MAPA_ORIGINAL_SIZE / 2 * _scaleY);
                _rotation = 0.0;

                RecalculateTransform();
                StatusMessageChanged?.Invoke(this, $"Calibracao completa! PupilaH={_raioPupilaH:F0}px, PupilaV={_raioPupilaV:F0}px, IrisH={_raioIrisH:F0}px, IrisV={_raioIrisV:F0}px");
            }
            catch (Exception ex)
            {
                StatusMessageChanged?.Invoke(this, $"Erro: {ex.Message}");
                ResetAlignment();
            }
        }

        private void RecalculateTransform()
        {
            // 🎯 Atualizar rotação calibrada (para uso no rendering polar)
            _rotacaoCalibrada = _rotation;

            var transformGroup = new TransformGroup();
            transformGroup.Children.Add(new ScaleTransform(_scaleX, _scaleY));

            if (Math.Abs(_rotation) > 0.01)
            {
                transformGroup.Children.Add(new RotateTransform(_rotation, MAPA_ORIGINAL_SIZE / 2, MAPA_ORIGINAL_SIZE / 2));
            }

            transformGroup.Children.Add(new TranslateTransform(_translateX, _translateY));
            TransformCalculated?.Invoke(this, transformGroup);
        }

        public void AdjustParameter(string parameterName, double value)
        {
            switch (parameterName)
            {
                case "ScaleX": ScaleX = value; break;
                case "ScaleY": ScaleY = value; break;
                case "TranslateX": TranslateX = value; break;
                case "TranslateY": TranslateY = value; break;
                case "Rotation": Rotation = value; break;
            }
        }

        public void ConfirmAlignment()
        {
            if (CurrentPhase == AlignmentPhase.ManualAdjust)
            {
                CurrentPhase = AlignmentPhase.Completed;
                StatusMessageChanged?.Invoke(this, "Alinhamento confirmado!");
            }
        }

        public void CancelAlignment()
        {
            ResetAlignment();
            StatusMessageChanged?.Invoke(this, "Alinhamento cancelado.");
        }

        private void ResetAlignment()
        {
            _centroPupila = new Point(0, 0);
            _bordaDireitaPupila = new Point(0, 0);
            _bordaTopoPupila = new Point(0, 0);
            _bordaDireitaIris = new Point(0, 0);
            _bordaTopoIris = new Point(0, 0);
            _scaleX = 1.0;
            _scaleY = 1.0;
            _translateX = 0.0;
            _translateY = 0.0;
            _rotation = 0.0;
            CurrentPhase = AlignmentPhase.Idle;
        }

        private void UpdateStatusMessage()
        {
            string message = CurrentPhase switch
            {
                AlignmentPhase.Idle => "Clique em 'Iniciar Alinhamento'.",
                AlignmentPhase.ClickCenterPupil => "1/5 Clique no CENTRO da pupila",
                AlignmentPhase.ClickRightPupil => "2/5 Clique na BORDA DIREITA da pupila",
                AlignmentPhase.ClickTopPupil => "3/5 Clique na BORDA SUPERIOR da pupila",
                AlignmentPhase.ClickRightIris => "4/5 Clique na BORDA DIREITA da iris",
                AlignmentPhase.ClickTopIris => "5/5 Clique na BORDA SUPERIOR da iris",
                AlignmentPhase.Calculating => "Calculando transformacao...",
                AlignmentPhase.ManualAdjust => "Ajuste fino com sliders. Clique 'Confirmar'.",
                AlignmentPhase.Completed => "Alinhamento completo!",
                _ => string.Empty
            };

            StatusMessageChanged?.Invoke(this, message);
        }

        public TransformGroup GetCurrentTransform()
        {
            var transformGroup = new TransformGroup();
            transformGroup.Children.Add(new ScaleTransform(_scaleX, _scaleY));

            if (Math.Abs(_rotation) > 0.01)
            {
                transformGroup.Children.Add(new RotateTransform(_rotation, MAPA_ORIGINAL_SIZE / 2, MAPA_ORIGINAL_SIZE / 2));
            }

            transformGroup.Children.Add(new TranslateTransform(_translateX, _translateY));
            return transformGroup;
        }
    }
}
