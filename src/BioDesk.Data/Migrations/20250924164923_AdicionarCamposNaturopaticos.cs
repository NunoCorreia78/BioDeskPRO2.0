using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace BioDesk.Data.Migrations
{
    /// <inheritdoc />
    public partial class AdicionarCamposNaturopaticos : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Pacientes",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Nome = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    DataNascimento = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Email = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    Telefone = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    Genero = table.Column<string>(type: "TEXT", maxLength: 10, nullable: true),
                    EstadoCivil = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    Profissao = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    Morada = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    ContatoEmergencia = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    TelefoneEmergencia = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    HistoricoMedicoFamiliar = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    HistoricoMedicoPessoal = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    MedicacaoAtual = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    SuplementosAtuais = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    Alergias = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    IntoleranciasAlimentares = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    SintomasPrincipais = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    SintomasSecundarios = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    InicioSintomas = table.Column<DateTime>(type: "TEXT", nullable: true),
                    HistoricoTraumas = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    CirurgiasAnteriores = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    PadroesAlimentares = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    QualidadeSono = table.Column<int>(type: "INTEGER", nullable: true),
                    PatternSono = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    NivelStress = table.Column<int>(type: "INTEGER", nullable: true),
                    NivelAtividadeFisica = table.Column<int>(type: "INTEGER", nullable: true),
                    TipoExercicio = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    Fumador = table.Column<bool>(type: "INTEGER", nullable: false),
                    ConsumoAlcool = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    ConsumoAgua = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    OutrosHabitos = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    Altura = table.Column<decimal>(type: "TEXT", nullable: true),
                    Peso = table.Column<decimal>(type: "TEXT", nullable: true),
                    PressaoSistolica = table.Column<int>(type: "INTEGER", nullable: true),
                    PressaoDiastolica = table.Column<int>(type: "INTEGER", nullable: true),
                    FrequenciaCardiaca = table.Column<int>(type: "INTEGER", nullable: true),
                    PosturaPrincipal = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    AvaliacaoPostural = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    TestesOrtopedicos = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    PontosTensao = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    AmplitudeMovimento = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    PalpacaoTecidual = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    ObservacoesExameFisico = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    EstadoChakraPrincipal = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    AvaliacacaoChakras = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    EstadoMeridianos = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    TestesEnergeticos = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    FrequenciasDetectadas = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    BloqueiosEnergeticos = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    NivelVitalidade = table.Column<int>(type: "INTEGER", nullable: true),
                    AuralEnergetica = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    DiagnosticoEnergetico = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    TratamentosOsteopaticos = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    ProtocolosNaturopaticos = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    SuplementacaoRecomendada = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    TerapiasComplementares = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    ExerciciosRecomendados = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    MudancasEstiloVida = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    FrequenciaSessoes = table.Column<int>(type: "INTEGER", nullable: true),
                    ProximaConsulta = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ObjetivosTratamento = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    NotasSessoes = table.Column<string>(type: "TEXT", maxLength: 5000, nullable: true),
                    ProgressoSintomas = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    AjustesTratamento = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    ResultadosTestes = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    UltimaSessao = table.Column<DateTime>(type: "TEXT", nullable: true),
                    NumeroSessoesRealizadas = table.Column<int>(type: "INTEGER", nullable: true),
                    ObservacoesGerais = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    CriadoEm = table.Column<DateTime>(type: "TEXT", nullable: false),
                    AtualizadoEm = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Pacientes", x => x.Id);
                });

            migrationBuilder.InsertData(
                table: "Pacientes",
                columns: new[] { "Id", "AjustesTratamento", "Alergias", "Altura", "AmplitudeMovimento", "AtualizadoEm", "AuralEnergetica", "AvaliacacaoChakras", "AvaliacaoPostural", "BloqueiosEnergeticos", "CirurgiasAnteriores", "ConsumoAgua", "ConsumoAlcool", "ContatoEmergencia", "CriadoEm", "DataNascimento", "DiagnosticoEnergetico", "Email", "EstadoChakraPrincipal", "EstadoCivil", "EstadoMeridianos", "ExerciciosRecomendados", "FrequenciaCardiaca", "FrequenciaSessoes", "FrequenciasDetectadas", "Fumador", "Genero", "HistoricoMedicoFamiliar", "HistoricoMedicoPessoal", "HistoricoTraumas", "InicioSintomas", "IntoleranciasAlimentares", "MedicacaoAtual", "Morada", "MudancasEstiloVida", "NivelAtividadeFisica", "NivelStress", "NivelVitalidade", "Nome", "NotasSessoes", "NumeroSessoesRealizadas", "ObjetivosTratamento", "ObservacoesExameFisico", "ObservacoesGerais", "OutrosHabitos", "PadroesAlimentares", "PalpacaoTecidual", "PatternSono", "Peso", "PontosTensao", "PosturaPrincipal", "PressaoDiastolica", "PressaoSistolica", "Profissao", "ProgressoSintomas", "ProtocolosNaturopaticos", "ProximaConsulta", "QualidadeSono", "ResultadosTestes", "SintomasPrincipais", "SintomasSecundarios", "SuplementacaoRecomendada", "SuplementosAtuais", "Telefone", "TelefoneEmergencia", "TerapiasComplementares", "TestesEnergeticos", "TestesOrtopedicos", "TipoExercicio", "TratamentosOsteopaticos", "UltimaSessao" },
                values: new object[,]
                {
                    { 1, null, null, null, null, new DateTime(2025, 9, 22, 17, 49, 22, 197, DateTimeKind.Local).AddTicks(8667), null, null, null, null, null, null, null, null, new DateTime(2025, 8, 25, 17, 49, 22, 197, DateTimeKind.Local).AddTicks(8667), new DateTime(1985, 3, 15, 0, 0, 0, 0, DateTimeKind.Unspecified), null, "ana.silva@email.com", null, null, null, null, null, null, null, false, null, null, null, null, null, null, null, null, null, null, null, null, "Ana Silva", null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, "912345678", null, null, null, null, null, null, null },
                    { 2, null, null, null, null, new DateTime(2025, 9, 19, 17, 49, 22, 197, DateTimeKind.Local).AddTicks(8667), null, null, null, null, null, null, null, null, new DateTime(2025, 8, 30, 17, 49, 22, 197, DateTimeKind.Local).AddTicks(8667), new DateTime(1978, 7, 22, 0, 0, 0, 0, DateTimeKind.Unspecified), null, "joao.ferreira@email.com", null, null, null, null, null, null, null, false, null, null, null, null, null, null, null, null, null, null, null, null, "João Ferreira", null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, "925678912", null, null, null, null, null, null, null },
                    { 3, null, null, null, null, new DateTime(2025, 9, 23, 17, 49, 22, 197, DateTimeKind.Local).AddTicks(8667), null, null, null, null, null, null, null, null, new DateTime(2025, 9, 4, 17, 49, 22, 197, DateTimeKind.Local).AddTicks(8667), new DateTime(1992, 11, 8, 0, 0, 0, 0, DateTimeKind.Unspecified), null, "maria.costa@email.com", null, null, null, null, null, null, null, false, null, null, null, null, null, null, null, null, null, null, null, null, "Maria Costa", null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, "934567823", null, null, null, null, null, null, null }
                });

            migrationBuilder.CreateIndex(
                name: "IX_Paciente_Unique",
                table: "Pacientes",
                columns: new[] { "Nome", "DataNascimento" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Pacientes");
        }
    }
}
