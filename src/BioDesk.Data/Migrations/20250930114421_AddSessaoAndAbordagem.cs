using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace BioDesk.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddSessaoAndAbordagem : Migration
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
                    NumeroProcesso = table.Column<string>(type: "TEXT", nullable: false),
                    NomeCompleto = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    DataNascimento = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Genero = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    NomePreferido = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    NIF = table.Column<string>(type: "TEXT", maxLength: 9, nullable: true),
                    Nacionalidade = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    EstadoCivil = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    Profissao = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    Proveniencia = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    ProvenienciaOutro = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    DataCriacao = table.Column<DateTime>(type: "TEXT", nullable: false),
                    DataUltimaAtualizacao = table.Column<DateTime>(type: "TEXT", nullable: true),
                    EstadoRegisto = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    ProgressoAbas = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Pacientes", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Consentimentos",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    PacienteId = table.Column<int>(type: "INTEGER", nullable: false),
                    TipoTratamento = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    DescricaoTratamento = table.Column<string>(type: "TEXT", nullable: false),
                    PersonalizacaoTratamento = table.Column<string>(type: "TEXT", nullable: true),
                    NaturezaProcedimento = table.Column<string>(type: "TEXT", nullable: true),
                    BeneficiosEsperados = table.Column<string>(type: "TEXT", nullable: true),
                    RiscosEfeitosSecundarios = table.Column<string>(type: "TEXT", nullable: true),
                    AlternativasDisponiveis = table.Column<string>(type: "TEXT", nullable: true),
                    Contraindicacoes = table.Column<string>(type: "TEXT", nullable: true),
                    DuracaoEstimadaSessoes = table.Column<int>(type: "INTEGER", nullable: true),
                    FrequenciaSessoes = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    CustoPorSessao = table.Column<decimal>(type: "decimal(10,2)", nullable: true),
                    CustoTotalEstimado = table.Column<decimal>(type: "decimal(10,2)", nullable: true),
                    PoliticaCancelamento = table.Column<string>(type: "TEXT", nullable: true),
                    CompreendeNatureza = table.Column<bool>(type: "INTEGER", nullable: false),
                    InformadoRiscos = table.Column<bool>(type: "INTEGER", nullable: false),
                    OportunidadePerguntas = table.Column<bool>(type: "INTEGER", nullable: false),
                    ConsenteTratamento = table.Column<bool>(type: "INTEGER", nullable: false),
                    QuestoesPreocupacoes = table.Column<string>(type: "TEXT", nullable: true),
                    AssinaturaDigital = table.Column<string>(type: "TEXT", nullable: true),
                    DataHoraAssinatura = table.Column<DateTime>(type: "TEXT", nullable: true),
                    EnderecoIPAssinatura = table.Column<string>(type: "TEXT", maxLength: 45, nullable: true),
                    Estado = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    DataExpiracao = table.Column<DateTime>(type: "TEXT", nullable: true),
                    MotivoRevogacao = table.Column<string>(type: "TEXT", nullable: true),
                    DataCriacao = table.Column<DateTime>(type: "TEXT", nullable: false),
                    DataAtualizacao = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Consentimentos", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Consentimentos_Pacientes_PacienteId",
                        column: x => x.PacienteId,
                        principalTable: "Pacientes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Consultas",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    PacienteId = table.Column<int>(type: "INTEGER", nullable: false),
                    DataHoraConsulta = table.Column<DateTime>(type: "TEXT", nullable: false),
                    TipoConsulta = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    DuracaoPrevista = table.Column<int>(type: "INTEGER", nullable: false),
                    DuracaoReal = table.Column<int>(type: "INTEGER", nullable: true),
                    QueixaPrincipal = table.Column<string>(type: "TEXT", nullable: false),
                    HistoriaDoencaAtual = table.Column<string>(type: "TEXT", nullable: true),
                    RevisaoSistemas = table.Column<string>(type: "TEXT", nullable: true),
                    PressaoArterial = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    Peso = table.Column<decimal>(type: "decimal(5,2)", nullable: true),
                    Altura = table.Column<decimal>(type: "decimal(5,1)", nullable: true),
                    Temperatura = table.Column<decimal>(type: "decimal(4,1)", nullable: true),
                    FrequenciaCardiaca = table.Column<int>(type: "INTEGER", nullable: true),
                    ExameFisico = table.Column<string>(type: "TEXT", nullable: true),
                    TestesAvaliacoes = table.Column<string>(type: "TEXT", nullable: true),
                    DiagnosticoPrincipal = table.Column<string>(type: "TEXT", nullable: false),
                    DiagnosticosSecundarios = table.Column<string>(type: "TEXT", nullable: true),
                    Prognostico = table.Column<string>(type: "TEXT", nullable: true),
                    TratamentosPrescritos = table.Column<string>(type: "TEXT", nullable: true),
                    RecomendacoesGerais = table.Column<string>(type: "TEXT", nullable: true),
                    ProximoSeguimento = table.Column<DateTime>(type: "TEXT", nullable: true),
                    Valor = table.Column<decimal>(type: "decimal(10,2)", nullable: true),
                    EstadoPagamento = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    DataPagamento = table.Column<DateTime>(type: "TEXT", nullable: true),
                    MetodoPagamento = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    Estado = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    ObservacoesInternas = table.Column<string>(type: "TEXT", nullable: true),
                    DataCriacao = table.Column<DateTime>(type: "TEXT", nullable: false),
                    DataAtualizacao = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Consultas", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Consultas_Pacientes_PacienteId",
                        column: x => x.PacienteId,
                        principalTable: "Pacientes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Contactos",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    PacienteId = table.Column<int>(type: "INTEGER", nullable: false),
                    RuaAvenida = table.Column<string>(type: "TEXT", maxLength: 300, nullable: true),
                    Numero = table.Column<string>(type: "TEXT", maxLength: 10, nullable: true),
                    AndarFraccao = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    CodigoPostal = table.Column<string>(type: "TEXT", maxLength: 8, nullable: true),
                    Localidade = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    Distrito = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    TelefonePrincipal = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    TelefoneAlternativo = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    EmailPrincipal = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    EmailAlternativo = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Contactos", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Contactos_Pacientes_PacienteId",
                        column: x => x.PacienteId,
                        principalTable: "Pacientes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "HistoricosMedicos",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    PacienteId = table.Column<int>(type: "INTEGER", nullable: false),
                    DoencasCronicas = table.Column<string>(type: "TEXT", nullable: true),
                    OutrasDoencas = table.Column<string>(type: "TEXT", nullable: true),
                    CirurgiasAnteriores = table.Column<string>(type: "TEXT", nullable: true),
                    Hospitalizacoes = table.Column<string>(type: "TEXT", nullable: true),
                    MedicacaoAtual = table.Column<string>(type: "TEXT", nullable: true),
                    Suplementos = table.Column<string>(type: "TEXT", nullable: true),
                    MedicamentosNaturais = table.Column<string>(type: "TEXT", nullable: true),
                    AlergiasMedicamentosas = table.Column<string>(type: "TEXT", nullable: true),
                    AlergiasAlimentares = table.Column<string>(type: "TEXT", nullable: true),
                    AlergiasAmbientais = table.Column<string>(type: "TEXT", nullable: true),
                    IntoleranciasAlimentares = table.Column<string>(type: "TEXT", nullable: true),
                    HistoriaFamiliar = table.Column<string>(type: "TEXT", nullable: true),
                    DoencasHereditarias = table.Column<string>(type: "TEXT", nullable: true),
                    ObservacoesFamiliares = table.Column<string>(type: "TEXT", nullable: true),
                    Tabagismo = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    DetalheTabagismo = table.Column<string>(type: "TEXT", nullable: true),
                    ConsumoAlcool = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    DetalheAlcool = table.Column<string>(type: "TEXT", nullable: true),
                    ExercicioFisico = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    DetalheExercicio = table.Column<string>(type: "TEXT", nullable: true),
                    HorasSono = table.Column<decimal>(type: "TEXT", nullable: true),
                    QualidadeSono = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    TipoDieta = table.Column<string>(type: "TEXT", maxLength: 30, nullable: true),
                    RestricaoesAlimentares = table.Column<string>(type: "TEXT", nullable: true),
                    ConsumoAguaDiario = table.Column<decimal>(type: "TEXT", nullable: true),
                    SuplementacaoAtual = table.Column<string>(type: "TEXT", nullable: true),
                    ConfirmaVeracidade = table.Column<bool>(type: "INTEGER", nullable: false),
                    CompreendImportancia = table.Column<bool>(type: "INTEGER", nullable: false),
                    ComprometeMudancas = table.Column<bool>(type: "INTEGER", nullable: false),
                    ObservacoesAdicionais = table.Column<string>(type: "TEXT", nullable: true),
                    DataCriacao = table.Column<DateTime>(type: "TEXT", nullable: false),
                    DataAtualizacao = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_HistoricosMedicos", x => x.Id);
                    table.ForeignKey(
                        name: "FK_HistoricosMedicos_Pacientes_PacienteId",
                        column: x => x.PacienteId,
                        principalTable: "Pacientes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "IrisAnalises",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    PacienteId = table.Column<int>(type: "INTEGER", nullable: false),
                    DataHoraAnalise = table.Column<DateTime>(type: "TEXT", nullable: false),
                    TipoEquipamento = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    ResolucaoCaptura = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    ConfiguracoesLuz = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    CaminhoImagemEsquerda = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    CaminhoImagemDireita = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    QualidadeImagemEsquerda = table.Column<int>(type: "INTEGER", nullable: true),
                    QualidadeImagemDireita = table.Column<int>(type: "INTEGER", nullable: true),
                    TamanhoFicheiroEsquerda = table.Column<long>(type: "INTEGER", nullable: true),
                    TamanhoFicheiroDireita = table.Column<long>(type: "INTEGER", nullable: true),
                    ObservacoesPorSetorEsquerda = table.Column<string>(type: "TEXT", nullable: true),
                    ObservacoesPorSetorDireita = table.Column<string>(type: "TEXT", nullable: true),
                    SistemaDigestivo = table.Column<string>(type: "TEXT", nullable: true),
                    SistemaCirculatorio = table.Column<string>(type: "TEXT", nullable: true),
                    SistemaNervoso = table.Column<string>(type: "TEXT", nullable: true),
                    SistemaRespiratorio = table.Column<string>(type: "TEXT", nullable: true),
                    SistemaGeniturinario = table.Column<string>(type: "TEXT", nullable: true),
                    SistemaMusculoEsqueletico = table.Column<string>(type: "TEXT", nullable: true),
                    InterpretacaoGeral = table.Column<string>(type: "TEXT", nullable: true),
                    PontosCriticos = table.Column<string>(type: "TEXT", nullable: true),
                    ComparacaoAnaliseAnterior = table.Column<string>(type: "TEXT", nullable: true),
                    TratamentosSugeridos = table.Column<string>(type: "TEXT", nullable: true),
                    SuplementacaoRecomendada = table.Column<string>(type: "TEXT", nullable: true),
                    MudancasEstiloVida = table.Column<string>(type: "TEXT", nullable: true),
                    FrequenciaProximaAnalise = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    ProfissionalAnalise = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    DuracaoSessao = table.Column<int>(type: "INTEGER", nullable: true),
                    ObservacoesTecnicas = table.Column<string>(type: "TEXT", nullable: true),
                    DataCriacao = table.Column<DateTime>(type: "TEXT", nullable: false),
                    DataAtualizacao = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IrisAnalises", x => x.Id);
                    table.ForeignKey(
                        name: "FK_IrisAnalises_Pacientes_PacienteId",
                        column: x => x.PacienteId,
                        principalTable: "Pacientes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Sessoes",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    PacienteId = table.Column<int>(type: "INTEGER", nullable: false),
                    DataHora = table.Column<DateTime>(type: "TEXT", nullable: false),
                    DuracaoMinutos = table.Column<int>(type: "INTEGER", nullable: false),
                    Motivo = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    Contexto = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    Achados = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    PressaoArterial = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    Peso = table.Column<decimal>(type: "TEXT", precision: 5, scale: 2, nullable: true),
                    Temperatura = table.Column<decimal>(type: "TEXT", precision: 4, scale: 2, nullable: true),
                    OutrasMedicoes = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    Avaliacao = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    Plano = table.Column<string>(type: "TEXT", maxLength: 3000, nullable: true),
                    CriadoEm = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ModificadoEm = table.Column<DateTime>(type: "TEXT", nullable: true),
                    IsDeleted = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Sessoes", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Sessoes_Pacientes_PacienteId",
                        column: x => x.PacienteId,
                        principalTable: "Pacientes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AbordagensSessoes",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    SessaoId = table.Column<int>(type: "INTEGER", nullable: false),
                    TipoAbordagem = table.Column<int>(type: "INTEGER", nullable: false),
                    Observacoes = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AbordagensSessoes", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AbordagensSessoes_Sessoes_SessaoId",
                        column: x => x.SessaoId,
                        principalTable: "Sessoes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.InsertData(
                table: "Pacientes",
                columns: new[] { "Id", "DataCriacao", "DataNascimento", "DataUltimaAtualizacao", "EstadoCivil", "EstadoRegisto", "Genero", "NIF", "Nacionalidade", "NomeCompleto", "NomePreferido", "NumeroProcesso", "Profissao", "ProgressoAbas", "Proveniencia", "ProvenienciaOutro" },
                values: new object[,]
                {
                    { 1, new DateTime(2025, 8, 31, 11, 44, 21, 27, DateTimeKind.Utc).AddTicks(6827), new DateTime(1980, 5, 15, 0, 0, 0, 0, DateTimeKind.Unspecified), null, "Casado", "Incompleto", "Masculino", null, "Portuguesa", "João Silva Santos", "João", "PAC-2025-001", "Engenheiro Informático", null, null, null },
                    { 2, new DateTime(2025, 9, 15, 11, 44, 21, 27, DateTimeKind.Utc).AddTicks(6838), new DateTime(1975, 11, 22, 0, 0, 0, 0, DateTimeKind.Unspecified), null, "Solteira", "Em Progresso", "Feminino", null, "Portuguesa", "Maria Fernanda Costa", "Maria", "PAC-2025-002", "Professora", "{\"Aba1\":true,\"Aba2\":true,\"Aba3\":false}", null, null },
                    { 3, new DateTime(2025, 9, 23, 11, 44, 21, 27, DateTimeKind.Utc).AddTicks(6843), new DateTime(1990, 3, 8, 0, 0, 0, 0, DateTimeKind.Unspecified), null, "União de Facto", "Completo", "Masculino", "123456789", "Portuguesa", "Carlos António Pereira", null, "PAC-2025-003", "Designer Gráfico", "{\"Aba1\":true,\"Aba2\":true,\"Aba3\":true,\"Aba4\":true,\"Aba5\":true,\"Aba6\":false}", null, null }
                });

            migrationBuilder.InsertData(
                table: "Contactos",
                columns: new[] { "Id", "AndarFraccao", "CodigoPostal", "Distrito", "EmailAlternativo", "EmailPrincipal", "Localidade", "Numero", "PacienteId", "RuaAvenida", "TelefoneAlternativo", "TelefonePrincipal" },
                values: new object[,]
                {
                    { 1, "2º Esq", "1000-001", "Lisboa", null, "joao.santos@email.com", "Lisboa", "123", 1, "Rua das Flores", null, "912345678" },
                    { 2, null, "4000-100", "Porto", null, "maria.costa@email.com", "Porto", "456", 2, "Avenida da República", "225551234", "923456789" },
                    { 3, null, "3000-050", "Coimbra", "c.pereira.design@email.com", "carlos.pereira@email.com", "Coimbra", "789", 3, "Praça do Comércio", null, "934567890" }
                });

            migrationBuilder.InsertData(
                table: "Sessoes",
                columns: new[] { "Id", "Achados", "Avaliacao", "Contexto", "CriadoEm", "DataHora", "DuracaoMinutos", "IsDeleted", "ModificadoEm", "Motivo", "OutrasMedicoes", "PacienteId", "Peso", "Plano", "PressaoArterial", "Temperatura" },
                values: new object[,]
                {
                    { 1, "Tensão muscular paravertebral L4-L5, trigger points bilateral", "Lombalgia mecânica aguda", "Após esforço físico no ginásio", new DateTime(2025, 8, 31, 12, 44, 21, 27, DateTimeKind.Local).AddTicks(7110), new DateTime(2025, 8, 31, 12, 44, 21, 27, DateTimeKind.Local).AddTicks(7098), 60, false, null, "Dor lombar aguda", null, 1, 78.5m, "HVLA L4-L5 + Protocolo anti-inflamatório + Repouso relativo 3 dias + Reavaliação 1 semana", "120/80", 36.5m },
                    { 2, "Melhoria 70%, tensão residual L5", "Evolução favorável", null, new DateTime(2025, 9, 7, 12, 44, 21, 27, DateTimeKind.Local).AddTicks(7121), new DateTime(2025, 9, 7, 12, 44, 21, 27, DateTimeKind.Local).AddTicks(7116), 45, false, null, "Reavaliação lombalgia", null, 1, 78.0m, "Alongamentos paravertebrais 10' 2x/dia + Manter atividade física moderada", "118/78", null },
                    { 3, "FC: 85 bpm, tensão cervical bilateral", "Stress ocupacional com somatização", "Período de trabalho intenso com deadlines apertados", new DateTime(2025, 9, 20, 12, 44, 21, 27, DateTimeKind.Local).AddTicks(7141), new DateTime(2025, 9, 20, 12, 44, 21, 27, DateTimeKind.Local).AddTicks(7137), 60, false, null, "Consulta de rotina + stress elevado", "FC: 85 bpm, padrão respiratório superficial", 1, null, "Protocolo anti-stress + Meditação 10' diária + Dieta anti-inflamatória + Ómega-3", "135/88", null },
                    { 4, "Trigger points trapézio superior bilateral, C5-C6 com restrição de mobilidade", "Cefaleia tensional de origem cervical", "Cefaleias tensionais há 6 meses, agravamento recente", new DateTime(2025, 9, 15, 12, 44, 21, 27, DateTimeKind.Local).AddTicks(7152), new DateTime(2025, 9, 15, 12, 44, 21, 27, DateTimeKind.Local).AddTicks(7147), 90, false, null, "Avaliação inicial - cefaleias recorrentes", "FC: 72 bpm", 2, 62.0m, "Manipulação C5-C6 + Exercícios posturais + Hidratação 2L/dia + Redução stress + Reavaliação 2 semanas", "125/82", 36.3m },
                    { 5, "Redução 60% frequência cefaleias, mobilidade cervical normalizada", "Excelente evolução", null, new DateTime(2025, 9, 29, 12, 44, 21, 27, DateTimeKind.Local).AddTicks(7162), new DateTime(2025, 9, 29, 12, 44, 21, 27, DateTimeKind.Local).AddTicks(7158), 60, false, null, "Reavaliação cefaleias + análise iridológica", null, 2, 61.5m, "Manter exercícios + Consulta follow-up 1 mês", "120/78", null },
                    { 6, "Edema leve joelho direito, mobilidade ombro esquerdo reduzida 20%, padrão de fadiga adrenal", "Síndrome inflamatório multifatorial + possível sobrecarga adrenal", "Dores articulares múltiplas (joelhos, ombros) + fadiga persistente há 3 meses", new DateTime(2025, 9, 25, 12, 44, 21, 27, DateTimeKind.Local).AddTicks(7173), new DateTime(2025, 9, 25, 12, 44, 21, 27, DateTimeKind.Local).AddTicks(7168), 120, false, null, "Consulta integrada - dor articular + fadiga crónica", "FC: 78 bpm, qualidade sono: 5/10", 3, 85.0m, "Osteopatia articular + Mesoterapia anti-inflamatória joelhos + Protocolo naturopático (Curcuma + Ómega-3 + Magnésio) + Dieta anti-inflamatória + Eliminar açúcar refinado + Sono 8h/noite + Reavaliação 3 semanas", "128/84", 36.4m }
                });

            migrationBuilder.InsertData(
                table: "AbordagensSessoes",
                columns: new[] { "Id", "Observacoes", "SessaoId", "TipoAbordagem" },
                values: new object[,]
                {
                    { 1, null, 1, 3 },
                    { 2, null, 2, 3 },
                    { 3, "Suplementação adaptogénica", 3, 1 },
                    { 4, "Equilíbrio energético", 3, 5 },
                    { 5, null, 4, 3 },
                    { 6, null, 5, 3 },
                    { 7, "Análise constitucional", 5, 4 },
                    { 8, "Técnicas articulares joelhos e ombro", 6, 3 },
                    { 9, "Infiltrações anti-inflamatórias", 6, 2 },
                    { 10, "Protocolo anti-inflamatório oral", 6, 1 }
                });

            migrationBuilder.CreateIndex(
                name: "IX_AbordagensSessoes_SessaoId_TipoAbordagem",
                table: "AbordagensSessoes",
                columns: new[] { "SessaoId", "TipoAbordagem" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Consentimentos_DataExpiracao",
                table: "Consentimentos",
                column: "DataExpiracao");

            migrationBuilder.CreateIndex(
                name: "IX_Consentimentos_Estado",
                table: "Consentimentos",
                column: "Estado");

            migrationBuilder.CreateIndex(
                name: "IX_Consentimentos_PacienteId",
                table: "Consentimentos",
                column: "PacienteId");

            migrationBuilder.CreateIndex(
                name: "IX_Consentimentos_TipoTratamento",
                table: "Consentimentos",
                column: "TipoTratamento");

            migrationBuilder.CreateIndex(
                name: "IX_Consultas_DataHoraConsulta",
                table: "Consultas",
                column: "DataHoraConsulta");

            migrationBuilder.CreateIndex(
                name: "IX_Consultas_Estado",
                table: "Consultas",
                column: "Estado");

            migrationBuilder.CreateIndex(
                name: "IX_Consultas_PacienteId",
                table: "Consultas",
                column: "PacienteId");

            migrationBuilder.CreateIndex(
                name: "IX_Consultas_TipoConsulta",
                table: "Consultas",
                column: "TipoConsulta");

            migrationBuilder.CreateIndex(
                name: "IX_Contactos_EmailPrincipal",
                table: "Contactos",
                column: "EmailPrincipal");

            migrationBuilder.CreateIndex(
                name: "IX_Contactos_PacienteId",
                table: "Contactos",
                column: "PacienteId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_HistoricosMedicos_PacienteId",
                table: "HistoricosMedicos",
                column: "PacienteId");

            migrationBuilder.CreateIndex(
                name: "IX_IrisAnalises_DataHoraAnalise",
                table: "IrisAnalises",
                column: "DataHoraAnalise");

            migrationBuilder.CreateIndex(
                name: "IX_IrisAnalises_PacienteId",
                table: "IrisAnalises",
                column: "PacienteId");

            migrationBuilder.CreateIndex(
                name: "IX_Pacientes_DataNascimento",
                table: "Pacientes",
                column: "DataNascimento");

            migrationBuilder.CreateIndex(
                name: "IX_Pacientes_NomeCompleto",
                table: "Pacientes",
                column: "NomeCompleto");

            migrationBuilder.CreateIndex(
                name: "IX_Pacientes_NumeroProcesso",
                table: "Pacientes",
                column: "NumeroProcesso",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Sessoes_DataHora",
                table: "Sessoes",
                column: "DataHora");

            migrationBuilder.CreateIndex(
                name: "IX_Sessoes_IsDeleted",
                table: "Sessoes",
                column: "IsDeleted");

            migrationBuilder.CreateIndex(
                name: "IX_Sessoes_PacienteId",
                table: "Sessoes",
                column: "PacienteId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AbordagensSessoes");

            migrationBuilder.DropTable(
                name: "Consentimentos");

            migrationBuilder.DropTable(
                name: "Consultas");

            migrationBuilder.DropTable(
                name: "Contactos");

            migrationBuilder.DropTable(
                name: "HistoricosMedicos");

            migrationBuilder.DropTable(
                name: "IrisAnalises");

            migrationBuilder.DropTable(
                name: "Sessoes");

            migrationBuilder.DropTable(
                name: "Pacientes");
        }
    }
}
