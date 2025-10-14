using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BioDesk.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddTerapiasBioenergeticasTables : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ImportacoesExcelLog",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    NomeFicheiro = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    CaminhoCompleto = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: false),
                    ImportadoEm = table.Column<DateTime>(type: "TEXT", nullable: false),
                    TotalLinhas = table.Column<int>(type: "INTEGER", nullable: false),
                    LinhasOk = table.Column<int>(type: "INTEGER", nullable: false),
                    LinhasWarnings = table.Column<int>(type: "INTEGER", nullable: false),
                    LinhasErros = table.Column<int>(type: "INTEGER", nullable: false),
                    DuracaoSegundos = table.Column<double>(type: "REAL", nullable: false),
                    Sucesso = table.Column<bool>(type: "INTEGER", nullable: false),
                    MensagemErro = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    DetalhesJson = table.Column<string>(type: "TEXT", nullable: true),
                    UtilizadorId = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ImportacoesExcelLog", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "PlanosTerapia",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    SessaoId = table.Column<int>(type: "INTEGER", nullable: false),
                    Nome = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Descricao = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    CriadoEm = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Estado = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PlanosTerapia", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PlanosTerapia_Sessoes_SessaoId",
                        column: x => x.SessaoId,
                        principalTable: "Sessoes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ProtocolosTerapeuticos",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ExternalId = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    Nome = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Categoria = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    FrequenciasJson = table.Column<string>(type: "TEXT", nullable: false),
                    AmplitudeV = table.Column<double>(type: "REAL", nullable: false),
                    LimiteCorrenteMa = table.Column<double>(type: "REAL", nullable: false),
                    FormaOnda = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    Modulacao = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    DuracaoMinPorFrequencia = table.Column<int>(type: "INTEGER", nullable: false),
                    Canal = table.Column<string>(type: "TEXT", maxLength: 10, nullable: false),
                    Contraindicacoes = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    Notas = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    CriadoEm = table.Column<DateTime>(type: "TEXT", nullable: false),
                    AtualizadoEm = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Ativo = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ProtocolosTerapeuticos", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SessoesTerapia",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    PlanoTerapiaId = table.Column<int>(type: "INTEGER", nullable: false),
                    InicioEm = table.Column<DateTime>(type: "TEXT", nullable: false),
                    FimEm = table.Column<DateTime>(type: "TEXT", nullable: true),
                    DuracaoTotalMinutos = table.Column<int>(type: "INTEGER", nullable: true),
                    TipoRng = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    RngSeed = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    HardwareUsado = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    TotalItensAplicados = table.Column<int>(type: "INTEGER", nullable: false),
                    ImprovementMedio = table.Column<double>(type: "REAL", nullable: false),
                    Estado = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    Observacoes = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    CriadoEm = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SessoesTerapia", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SessoesTerapia_PlanosTerapia_PlanoTerapiaId",
                        column: x => x.PlanoTerapiaId,
                        principalTable: "PlanosTerapia",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Terapias",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    PlanoTerapiaId = table.Column<int>(type: "INTEGER", nullable: false),
                    ProtocoloTerapeuticoId = table.Column<int>(type: "INTEGER", nullable: false),
                    Ordem = table.Column<int>(type: "INTEGER", nullable: false),
                    ValuePercent = table.Column<double>(type: "REAL", nullable: false),
                    ImprovementPercent = table.Column<double>(type: "REAL", nullable: false),
                    AlvoMelhoria = table.Column<double>(type: "REAL", nullable: false),
                    Aplicado = table.Column<bool>(type: "INTEGER", nullable: false),
                    AplicadoEm = table.Column<DateTime>(type: "TEXT", nullable: true),
                    DuracaoMinutos = table.Column<int>(type: "INTEGER", nullable: true),
                    NotasAplicacao = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    CriadoEm = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Terapias", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Terapias_PlanosTerapia_PlanoTerapiaId",
                        column: x => x.PlanoTerapiaId,
                        principalTable: "PlanosTerapia",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_Terapias_ProtocolosTerapeuticos_ProtocoloTerapeuticoId",
                        column: x => x.ProtocoloTerapeuticoId,
                        principalTable: "ProtocolosTerapeuticos",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "EventosHardware",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    SessaoTerapiaId = table.Column<int>(type: "INTEGER", nullable: false),
                    Timestamp = table.Column<DateTime>(type: "TEXT", nullable: false),
                    TipoEvento = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    Severidade = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    Mensagem = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    DetalhesJson = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    CodigoErro = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EventosHardware", x => x.Id);
                    table.ForeignKey(
                        name: "FK_EventosHardware_SessoesTerapia_SessaoTerapiaId",
                        column: x => x.SessaoTerapiaId,
                        principalTable: "SessoesTerapia",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "LeiturasBioenergeticas",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    SessaoTerapiaId = table.Column<int>(type: "INTEGER", nullable: false),
                    Timestamp = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Rms = table.Column<double>(type: "REAL", nullable: false),
                    Pico = table.Column<double>(type: "REAL", nullable: false),
                    FrequenciaDominante = table.Column<double>(type: "REAL", nullable: false),
                    PotenciaEspectral = table.Column<double>(type: "REAL", nullable: false),
                    Gsr = table.Column<double>(type: "REAL", nullable: true),
                    MetricasAdicionaisJson = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    Canal = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_LeiturasBioenergeticas", x => x.Id);
                    table.ForeignKey(
                        name: "FK_LeiturasBioenergeticas_SessoesTerapia_SessaoTerapiaId",
                        column: x => x.SessaoTerapiaId,
                        principalTable: "SessoesTerapia",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.UpdateData(
                table: "ConfiguracaoClinica",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataAtualizacao",
                value: new DateTime(2025, 10, 12, 19, 39, 50, 268, DateTimeKind.Utc).AddTicks(6151));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 12, 19, 39, 50, 267, DateTimeKind.Utc).AddTicks(6455));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 27, 19, 39, 50, 267, DateTimeKind.Utc).AddTicks(6470));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 10, 5, 19, 39, 50, 267, DateTimeKind.Utc).AddTicks(6473));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 12, 20, 39, 50, 267, DateTimeKind.Local).AddTicks(6790), new DateTime(2025, 9, 12, 20, 39, 50, 267, DateTimeKind.Local).AddTicks(6778) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 19, 20, 39, 50, 267, DateTimeKind.Local).AddTicks(6797), new DateTime(2025, 9, 19, 20, 39, 50, 267, DateTimeKind.Local).AddTicks(6794) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 2, 20, 39, 50, 267, DateTimeKind.Local).AddTicks(6804), new DateTime(2025, 10, 2, 20, 39, 50, 267, DateTimeKind.Local).AddTicks(6801) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 27, 20, 39, 50, 267, DateTimeKind.Local).AddTicks(6874), new DateTime(2025, 9, 27, 20, 39, 50, 267, DateTimeKind.Local).AddTicks(6822) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 11, 20, 39, 50, 267, DateTimeKind.Local).AddTicks(6881), new DateTime(2025, 10, 11, 20, 39, 50, 267, DateTimeKind.Local).AddTicks(6878) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 7, 20, 39, 50, 267, DateTimeKind.Local).AddTicks(6887), new DateTime(2025, 10, 7, 20, 39, 50, 267, DateTimeKind.Local).AddTicks(6884) });

            migrationBuilder.CreateIndex(
                name: "IX_EventosHardware_SessaoTerapiaId",
                table: "EventosHardware",
                column: "SessaoTerapiaId");

            migrationBuilder.CreateIndex(
                name: "IX_EventosHardware_Timestamp",
                table: "EventosHardware",
                column: "Timestamp");

            migrationBuilder.CreateIndex(
                name: "IX_EventosHardware_TipoEvento",
                table: "EventosHardware",
                column: "TipoEvento");

            migrationBuilder.CreateIndex(
                name: "IX_ImportacoesExcelLog_ImportadoEm",
                table: "ImportacoesExcelLog",
                column: "ImportadoEm");

            migrationBuilder.CreateIndex(
                name: "IX_ImportacoesExcelLog_Sucesso",
                table: "ImportacoesExcelLog",
                column: "Sucesso");

            migrationBuilder.CreateIndex(
                name: "IX_LeiturasBioenergeticas_SessaoTerapiaId",
                table: "LeiturasBioenergeticas",
                column: "SessaoTerapiaId");

            migrationBuilder.CreateIndex(
                name: "IX_LeiturasBioenergeticas_Timestamp",
                table: "LeiturasBioenergeticas",
                column: "Timestamp");

            migrationBuilder.CreateIndex(
                name: "IX_PlanosTerapia_SessaoId",
                table: "PlanosTerapia",
                column: "SessaoId");

            migrationBuilder.CreateIndex(
                name: "IX_ProtocolosTerapeuticos_Ativo",
                table: "ProtocolosTerapeuticos",
                column: "Ativo");

            migrationBuilder.CreateIndex(
                name: "IX_ProtocolosTerapeuticos_Categoria",
                table: "ProtocolosTerapeuticos",
                column: "Categoria");

            migrationBuilder.CreateIndex(
                name: "IX_ProtocolosTerapeuticos_ExternalId",
                table: "ProtocolosTerapeuticos",
                column: "ExternalId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ProtocolosTerapeuticos_Nome",
                table: "ProtocolosTerapeuticos",
                column: "Nome");

            migrationBuilder.CreateIndex(
                name: "IX_SessoesTerapia_Estado",
                table: "SessoesTerapia",
                column: "Estado");

            migrationBuilder.CreateIndex(
                name: "IX_SessoesTerapia_InicioEm",
                table: "SessoesTerapia",
                column: "InicioEm");

            migrationBuilder.CreateIndex(
                name: "IX_SessoesTerapia_PlanoTerapiaId",
                table: "SessoesTerapia",
                column: "PlanoTerapiaId");

            migrationBuilder.CreateIndex(
                name: "IX_Terapias_Ordem",
                table: "Terapias",
                column: "Ordem");

            migrationBuilder.CreateIndex(
                name: "IX_Terapias_PlanoTerapiaId",
                table: "Terapias",
                column: "PlanoTerapiaId");

            migrationBuilder.CreateIndex(
                name: "IX_Terapias_ProtocoloTerapeuticoId",
                table: "Terapias",
                column: "ProtocoloTerapeuticoId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "EventosHardware");

            migrationBuilder.DropTable(
                name: "ImportacoesExcelLog");

            migrationBuilder.DropTable(
                name: "LeiturasBioenergeticas");

            migrationBuilder.DropTable(
                name: "Terapias");

            migrationBuilder.DropTable(
                name: "SessoesTerapia");

            migrationBuilder.DropTable(
                name: "ProtocolosTerapeuticos");

            migrationBuilder.DropTable(
                name: "PlanosTerapia");

            migrationBuilder.UpdateData(
                table: "ConfiguracaoClinica",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataAtualizacao",
                value: new DateTime(2025, 10, 12, 18, 41, 29, 811, DateTimeKind.Utc).AddTicks(9596));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 12, 18, 41, 29, 811, DateTimeKind.Utc).AddTicks(8953));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 27, 18, 41, 29, 811, DateTimeKind.Utc).AddTicks(8969));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 10, 5, 18, 41, 29, 811, DateTimeKind.Utc).AddTicks(8975));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 12, 19, 41, 29, 811, DateTimeKind.Local).AddTicks(9370), new DateTime(2025, 9, 12, 19, 41, 29, 811, DateTimeKind.Local).AddTicks(9355) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 19, 19, 41, 29, 811, DateTimeKind.Local).AddTicks(9382), new DateTime(2025, 9, 19, 19, 41, 29, 811, DateTimeKind.Local).AddTicks(9377) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 2, 19, 41, 29, 811, DateTimeKind.Local).AddTicks(9392), new DateTime(2025, 10, 2, 19, 41, 29, 811, DateTimeKind.Local).AddTicks(9388) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 27, 19, 41, 29, 811, DateTimeKind.Local).AddTicks(9447), new DateTime(2025, 9, 27, 19, 41, 29, 811, DateTimeKind.Local).AddTicks(9410) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 11, 19, 41, 29, 811, DateTimeKind.Local).AddTicks(9457), new DateTime(2025, 10, 11, 19, 41, 29, 811, DateTimeKind.Local).AddTicks(9453) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 7, 19, 41, 29, 811, DateTimeKind.Local).AddTicks(9479), new DateTime(2025, 10, 7, 19, 41, 29, 811, DateTimeKind.Local).AddTicks(9474) });
        }
    }
}
