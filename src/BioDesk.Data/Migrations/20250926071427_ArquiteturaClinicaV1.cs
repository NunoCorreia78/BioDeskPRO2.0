using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BioDesk.Data.Migrations
{
    /// <inheritdoc />
    public partial class ArquiteturaClinicaV1 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AvaliacoesClinicas",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    PacienteId = table.Column<int>(type: "INTEGER", nullable: false),
                    DataCriacao = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UltimaAtualizacao = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Observacoes = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    IsCompleta = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AvaliacoesClinicas", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AvaliacoesClinicas_Pacientes_PacienteId",
                        column: x => x.PacienteId,
                        principalTable: "Pacientes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "SessoesClinicas",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    PacienteId = table.Column<int>(type: "INTEGER", nullable: false),
                    DataSessao = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Motivo = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    HistoriaQueixaAtual = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    ObservacoesSessao = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: false),
                    PlanoTerapeutico = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: false),
                    Profissional = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Status = table.Column<int>(type: "INTEGER", nullable: false),
                    HouveAlteracoesMedicacao = table.Column<bool>(type: "INTEGER", nullable: false),
                    HouveAlteracoesAlergias = table.Column<bool>(type: "INTEGER", nullable: false),
                    HouveAlteracoesCronicas = table.Column<bool>(type: "INTEGER", nullable: false),
                    CriadoEm = table.Column<DateTime>(type: "TEXT", nullable: false),
                    AtualizadoEm = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SessoesClinicas", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SessoesClinicas_Pacientes_PacienteId",
                        column: x => x.PacienteId,
                        principalTable: "Pacientes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "EstilosVida",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    AvaliacaoClinicaId = table.Column<int>(type: "INTEGER", nullable: false),
                    AlimentacaoJson = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    Hidratacao = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    ExercicioJson = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    ExercicioFrequencia = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    Tabaco = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    TabacoQuantidade = table.Column<int>(type: "INTEGER", nullable: true),
                    Alcool = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    Cafeina = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    Stress = table.Column<int>(type: "INTEGER", nullable: true),
                    SonoJson = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    Observacoes = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EstilosVida", x => x.Id);
                    table.ForeignKey(
                        name: "FK_EstilosVida_AvaliacoesClinicas_AvaliacaoClinicaId",
                        column: x => x.AvaliacaoClinicaId,
                        principalTable: "AvaliacoesClinicas",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "HistoriaClinicas",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    AvaliacaoClinicaId = table.Column<int>(type: "INTEGER", nullable: false),
                    DoencasCronicasJson = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    CirurgiasJson = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    TiposAlergiasJson = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    EspecificarAlergias = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    SemAlergias = table.Column<bool>(type: "INTEGER", nullable: false),
                    MedicacaoAtualJson = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    SemMedicacao = table.Column<bool>(type: "INTEGER", nullable: false),
                    SuplementacaoJson = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    SemSuplementacao = table.Column<bool>(type: "INTEGER", nullable: false),
                    VacinacaoJson = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    VacinacaoNaoAplicavel = table.Column<bool>(type: "INTEGER", nullable: false),
                    Observacoes = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_HistoriaClinicas", x => x.Id);
                    table.ForeignKey(
                        name: "FK_HistoriaClinicas_AvaliacoesClinicas_AvaliacaoClinicaId",
                        column: x => x.AvaliacaoClinicaId,
                        principalTable: "AvaliacoesClinicas",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "HistoriasFamiliares",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    AvaliacaoClinicaId = table.Column<int>(type: "INTEGER", nullable: false),
                    AntecedentesJson = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    ParentescoJson = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    Observacoes = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_HistoriasFamiliares", x => x.Id);
                    table.ForeignKey(
                        name: "FK_HistoriasFamiliares_AvaliacoesClinicas_AvaliacaoClinicaId",
                        column: x => x.AvaliacaoClinicaId,
                        principalTable: "AvaliacoesClinicas",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MotivosConsulta",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    AvaliacaoClinicaId = table.Column<int>(type: "INTEGER", nullable: false),
                    MotivosJson = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    OutroMotivo = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    Localizacao = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    Lado = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    DataInicio = table.Column<DateTime>(type: "TEXT", nullable: true),
                    Duracao = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    Evolucao = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    Intensidade = table.Column<int>(type: "INTEGER", nullable: true),
                    CaraterJson = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    FatoresAgravantesJson = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    FatoresAlivioJson = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    Observacoes = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MotivosConsulta", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MotivosConsulta_AvaliacoesClinicas_AvaliacaoClinicaId",
                        column: x => x.AvaliacaoClinicaId,
                        principalTable: "AvaliacoesClinicas",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "RevisoesSistemas",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    AvaliacaoClinicaId = table.Column<int>(type: "INTEGER", nullable: false),
                    CardiovascularJson = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    CardiovascularObs = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    RespiratorioJson = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    RespiratorioObs = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    DigestivoJson = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    DigestivoObs = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    RenalUrinarioJson = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    RenalUrinarioObs = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    EndocrinoMetabolicoJson = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    EndocrinoMetabolicoObs = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    MusculoEsqueleticoJson = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    MusculoEsqueleticoObs = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    NeurologicoJson = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    NeurologicoObs = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    PeleJson = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    PeleObs = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    HumorSonoEnergiaJson = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    HumorSonoEnergiaObs = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RevisoesSistemas", x => x.Id);
                    table.ForeignKey(
                        name: "FK_RevisoesSistemas_AvaliacoesClinicas_AvaliacaoClinicaId",
                        column: x => x.AvaliacaoClinicaId,
                        principalTable: "AvaliacoesClinicas",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AlteracoesMedicacao",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    SessaoClinicaId = table.Column<int>(type: "INTEGER", nullable: false),
                    NomeMedicacao = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    TipoAlteracao = table.Column<int>(type: "INTEGER", nullable: false),
                    DoseAnterior = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    NovaDosse = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Via = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    Frequencia = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Indicacao = table.Column<string>(type: "TEXT", maxLength: 300, nullable: false),
                    MotivoAlteracao = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    DataAlteracao = table.Column<DateTime>(type: "TEXT", nullable: false),
                    AtualizarPermanente = table.Column<bool>(type: "INTEGER", nullable: false),
                    Observacoes = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AlteracoesMedicacao", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AlteracoesMedicacao_SessoesClinicas_SessaoClinicaId",
                        column: x => x.SessaoClinicaId,
                        principalTable: "SessoesClinicas",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "DeclaracoesLegais",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    SessaoClinicaId = table.Column<int>(type: "INTEGER", nullable: false),
                    ConteudoDeclaracao = table.Column<string>(type: "TEXT", nullable: false),
                    DataGeracao = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Versao = table.Column<int>(type: "INTEGER", nullable: false),
                    Status = table.Column<int>(type: "INTEGER", nullable: false),
                    AssinadoPaciente = table.Column<bool>(type: "INTEGER", nullable: false),
                    DataAssinaturaPaciente = table.Column<DateTime>(type: "TEXT", nullable: true),
                    MetodoAssinaturaPaciente = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    AssinadoProfissional = table.Column<bool>(type: "INTEGER", nullable: false),
                    DataAssinaturaProfissional = table.Column<DateTime>(type: "TEXT", nullable: true),
                    NomeProfissional = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    RegistoProfissional = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    ConsentimentosAtivos = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false),
                    HashIntegridade = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    Observacoes = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    UltimaAtualizacao = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DeclaracoesLegais", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DeclaracoesLegais_SessoesClinicas_SessaoClinicaId",
                        column: x => x.SessaoClinicaId,
                        principalTable: "SessoesClinicas",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MedicacaoAtual",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    PacienteId = table.Column<int>(type: "INTEGER", nullable: false),
                    Nome = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Codigo = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    Dose = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Via = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    Frequencia = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Indicacao = table.Column<string>(type: "TEXT", maxLength: 300, nullable: false),
                    DataInicio = table.Column<DateTime>(type: "TEXT", nullable: false),
                    DataSuspensao = table.Column<DateTime>(type: "TEXT", nullable: true),
                    Estado = table.Column<int>(type: "INTEGER", nullable: false),
                    Tipo = table.Column<int>(type: "INTEGER", nullable: false),
                    Adesao = table.Column<int>(type: "INTEGER", nullable: false),
                    EfeitosAdversos = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    Observacoes = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: false),
                    ReverEm = table.Column<DateTime>(type: "TEXT", nullable: true),
                    SessaoOrigemId = table.Column<int>(type: "INTEGER", nullable: true),
                    UltimaAtualizacao = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MedicacaoAtual", x => x.Id);
                    table.ForeignKey(
                        name: "FK_MedicacaoAtual_Pacientes_PacienteId",
                        column: x => x.PacienteId,
                        principalTable: "Pacientes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_MedicacaoAtual_SessoesClinicas_SessaoOrigemId",
                        column: x => x.SessaoOrigemId,
                        principalTable: "SessoesClinicas",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "RedFlags",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    SessaoClinicaId = table.Column<int>(type: "INTEGER", nullable: false),
                    Tipo = table.Column<int>(type: "INTEGER", nullable: false),
                    Descricao = table.Column<string>(type: "TEXT", maxLength: 300, nullable: false),
                    NivelRisco = table.Column<int>(type: "INTEGER", nullable: false),
                    Estado = table.Column<int>(type: "INTEGER", nullable: false),
                    AcoesTomadas = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: false),
                    DataIdentificacao = table.Column<DateTime>(type: "TEXT", nullable: false),
                    DataResolucao = table.Column<DateTime>(type: "TEXT", nullable: true),
                    AtualizarPermanente = table.Column<bool>(type: "INTEGER", nullable: false),
                    Observacoes = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RedFlags", x => x.Id);
                    table.ForeignKey(
                        name: "FK_RedFlags_SessoesClinicas_SessaoClinicaId",
                        column: x => x.SessaoClinicaId,
                        principalTable: "SessoesClinicas",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "SintomasAtivos",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    PacienteId = table.Column<int>(type: "INTEGER", nullable: false),
                    Nome = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Sistema = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    IntensidadeAtual = table.Column<int>(type: "INTEGER", nullable: false),
                    Estado = table.Column<int>(type: "INTEGER", nullable: false),
                    Prioridade = table.Column<int>(type: "INTEGER", nullable: false),
                    PrimeiraOcorrencia = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UltimaAtualizacao = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ReverEm = table.Column<DateTime>(type: "TEXT", nullable: true),
                    ObservacoesPermanentes = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: false),
                    SessaoOrigemId = table.Column<int>(type: "INTEGER", nullable: true),
                    HistoricoIntensidades = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SintomasAtivos", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SintomasAtivos_Pacientes_PacienteId",
                        column: x => x.PacienteId,
                        principalTable: "Pacientes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_SintomasAtivos_SessoesClinicas_SessaoOrigemId",
                        column: x => x.SessaoOrigemId,
                        principalTable: "SessoesClinicas",
                        principalColumn: "Id");
                });

            migrationBuilder.CreateTable(
                name: "SintomasSessao",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    SessaoClinicaId = table.Column<int>(type: "INTEGER", nullable: false),
                    Nome = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Sistema = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Intensidade = table.Column<int>(type: "INTEGER", nullable: false),
                    IntensidadeAnterior = table.Column<int>(type: "INTEGER", nullable: true),
                    Localizacao = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Carater = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Frequencia = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Desencadeantes = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    Aliviantes = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    Estado = table.Column<int>(type: "INTEGER", nullable: false),
                    TrabalharHoje = table.Column<bool>(type: "INTEGER", nullable: false),
                    AtualizarPermanente = table.Column<bool>(type: "INTEGER", nullable: false),
                    Relevante = table.Column<bool>(type: "INTEGER", nullable: false),
                    Persistente = table.Column<bool>(type: "INTEGER", nullable: false),
                    NivelRisco = table.Column<int>(type: "INTEGER", nullable: false),
                    Observacoes = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: false),
                    PrimeiroRegisto = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UltimaAtualizacao = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SintomasSessao", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SintomasSessao_SessoesClinicas_SessaoClinicaId",
                        column: x => x.SessaoClinicaId,
                        principalTable: "SessoesClinicas",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 12, 8, 14, 27, 216, DateTimeKind.Local).AddTicks(7638), new DateTime(2025, 9, 12, 8, 14, 27, 216, DateTimeKind.Local).AddTicks(7638) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 19, 8, 14, 27, 216, DateTimeKind.Local).AddTicks(7638), new DateTime(2025, 9, 19, 8, 14, 27, 216, DateTimeKind.Local).AddTicks(7638) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 16, 8, 14, 27, 216, DateTimeKind.Local).AddTicks(7638), new DateTime(2025, 9, 16, 8, 14, 27, 216, DateTimeKind.Local).AddTicks(7638) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 28, 8, 14, 27, 216, DateTimeKind.Local).AddTicks(7638), new DateTime(2025, 9, 23, 8, 14, 27, 216, DateTimeKind.Local).AddTicks(7638) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 24, 8, 14, 27, 216, DateTimeKind.Local).AddTicks(7638), new DateTime(2025, 8, 27, 8, 14, 27, 216, DateTimeKind.Local).AddTicks(7638) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 21, 8, 14, 27, 216, DateTimeKind.Local).AddTicks(7638), new DateTime(2025, 9, 1, 8, 14, 27, 216, DateTimeKind.Local).AddTicks(7638) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 25, 8, 14, 27, 216, DateTimeKind.Local).AddTicks(7638), new DateTime(2025, 9, 6, 8, 14, 27, 216, DateTimeKind.Local).AddTicks(7638) });

            migrationBuilder.CreateIndex(
                name: "IX_AlteracoesMedicacao_SessaoClinicaId",
                table: "AlteracoesMedicacao",
                column: "SessaoClinicaId");

            migrationBuilder.CreateIndex(
                name: "IX_AvaliacaoClinica_DataCriacao",
                table: "AvaliacoesClinicas",
                column: "DataCriacao");

            migrationBuilder.CreateIndex(
                name: "IX_AvaliacaoClinica_PacienteId",
                table: "AvaliacoesClinicas",
                column: "PacienteId");

            migrationBuilder.CreateIndex(
                name: "IX_DeclaracoesLegais_SessaoClinicaId",
                table: "DeclaracoesLegais",
                column: "SessaoClinicaId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_EstilosVida_AvaliacaoClinicaId",
                table: "EstilosVida",
                column: "AvaliacaoClinicaId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_HistoriaClinicas_AvaliacaoClinicaId",
                table: "HistoriaClinicas",
                column: "AvaliacaoClinicaId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_HistoriasFamiliares_AvaliacaoClinicaId",
                table: "HistoriasFamiliares",
                column: "AvaliacaoClinicaId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MedicacaoAtual_PacienteId_Estado",
                table: "MedicacaoAtual",
                columns: new[] { "PacienteId", "Estado" });

            migrationBuilder.CreateIndex(
                name: "IX_MedicacaoAtual_PacienteId_Nome_Dose",
                table: "MedicacaoAtual",
                columns: new[] { "PacienteId", "Nome", "Dose" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MedicacaoAtual_SessaoOrigemId",
                table: "MedicacaoAtual",
                column: "SessaoOrigemId");

            migrationBuilder.CreateIndex(
                name: "IX_MotivosConsulta_AvaliacaoClinicaId",
                table: "MotivosConsulta",
                column: "AvaliacaoClinicaId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RedFlags_Estado_NivelRisco",
                table: "RedFlags",
                columns: new[] { "Estado", "NivelRisco" });

            migrationBuilder.CreateIndex(
                name: "IX_RedFlags_SessaoClinicaId",
                table: "RedFlags",
                column: "SessaoClinicaId");

            migrationBuilder.CreateIndex(
                name: "IX_RevisoesSistemas_AvaliacaoClinicaId",
                table: "RevisoesSistemas",
                column: "AvaliacaoClinicaId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SessoesClinicas_PacienteId_DataSessao",
                table: "SessoesClinicas",
                columns: new[] { "PacienteId", "DataSessao" });

            migrationBuilder.CreateIndex(
                name: "IX_SintomasAtivos_PacienteId_Nome",
                table: "SintomasAtivos",
                columns: new[] { "PacienteId", "Nome" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SintomasAtivos_PacienteId_Prioridade",
                table: "SintomasAtivos",
                columns: new[] { "PacienteId", "Prioridade" });

            migrationBuilder.CreateIndex(
                name: "IX_SintomasAtivos_SessaoOrigemId",
                table: "SintomasAtivos",
                column: "SessaoOrigemId");

            migrationBuilder.CreateIndex(
                name: "IX_SintomasSessao_SessaoClinicaId",
                table: "SintomasSessao",
                column: "SessaoClinicaId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AlteracoesMedicacao");

            migrationBuilder.DropTable(
                name: "DeclaracoesLegais");

            migrationBuilder.DropTable(
                name: "EstilosVida");

            migrationBuilder.DropTable(
                name: "HistoriaClinicas");

            migrationBuilder.DropTable(
                name: "HistoriasFamiliares");

            migrationBuilder.DropTable(
                name: "MedicacaoAtual");

            migrationBuilder.DropTable(
                name: "MotivosConsulta");

            migrationBuilder.DropTable(
                name: "RedFlags");

            migrationBuilder.DropTable(
                name: "RevisoesSistemas");

            migrationBuilder.DropTable(
                name: "SintomasAtivos");

            migrationBuilder.DropTable(
                name: "SintomasSessao");

            migrationBuilder.DropTable(
                name: "AvaliacoesClinicas");

            migrationBuilder.DropTable(
                name: "SessoesClinicas");

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 11, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138), new DateTime(2025, 9, 11, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 18, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138), new DateTime(2025, 9, 18, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 15, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138), new DateTime(2025, 9, 15, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138) });

            migrationBuilder.UpdateData(
                table: "Consultas",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "DataConsulta", "DataCriacao" },
                values: new object[] { new DateTime(2025, 9, 27, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138), new DateTime(2025, 9, 22, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 23, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138), new DateTime(2025, 8, 26, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 20, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138), new DateTime(2025, 8, 31, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 24, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138), new DateTime(2025, 9, 5, 18, 2, 1, 390, DateTimeKind.Local).AddTicks(7138) });
        }
    }
}
