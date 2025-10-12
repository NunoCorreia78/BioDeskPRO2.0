using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BioDesk.Data.Migrations
{
    /// <inheritdoc />
    public partial class RemoveHistoricoMedicoTable : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "HistoricosMedicos");

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

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "HistoricosMedicos",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    PacienteId = table.Column<int>(type: "INTEGER", nullable: false),
                    AlergiasAlimentares = table.Column<string>(type: "TEXT", nullable: true),
                    AlergiasAmbientais = table.Column<string>(type: "TEXT", nullable: true),
                    AlergiasMedicamentosas = table.Column<string>(type: "TEXT", nullable: true),
                    CirurgiasAnteriores = table.Column<string>(type: "TEXT", nullable: true),
                    CompreendImportancia = table.Column<bool>(type: "INTEGER", nullable: false),
                    ComprometeMudancas = table.Column<bool>(type: "INTEGER", nullable: false),
                    ConfirmaVeracidade = table.Column<bool>(type: "INTEGER", nullable: false),
                    ConsumoAguaDiario = table.Column<decimal>(type: "TEXT", nullable: true),
                    ConsumoAlcool = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    DataAtualizacao = table.Column<DateTime>(type: "TEXT", nullable: true),
                    DataCriacao = table.Column<DateTime>(type: "TEXT", nullable: false),
                    DetalheAlcool = table.Column<string>(type: "TEXT", nullable: true),
                    DetalheExercicio = table.Column<string>(type: "TEXT", nullable: true),
                    DetalheTabagismo = table.Column<string>(type: "TEXT", nullable: true),
                    DoencasCronicas = table.Column<string>(type: "TEXT", nullable: true),
                    DoencasHereditarias = table.Column<string>(type: "TEXT", nullable: true),
                    ExercicioFisico = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    HistoriaFamiliar = table.Column<string>(type: "TEXT", nullable: true),
                    HorasSono = table.Column<decimal>(type: "TEXT", nullable: true),
                    Hospitalizacoes = table.Column<string>(type: "TEXT", nullable: true),
                    IntoleranciasAlimentares = table.Column<string>(type: "TEXT", nullable: true),
                    MedicacaoAtual = table.Column<string>(type: "TEXT", nullable: true),
                    MedicamentosNaturais = table.Column<string>(type: "TEXT", nullable: true),
                    ObservacoesAdicionais = table.Column<string>(type: "TEXT", nullable: true),
                    ObservacoesFamiliares = table.Column<string>(type: "TEXT", nullable: true),
                    OutrasDoencas = table.Column<string>(type: "TEXT", nullable: true),
                    QualidadeSono = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    RestricaoesAlimentares = table.Column<string>(type: "TEXT", nullable: true),
                    SuplementacaoAtual = table.Column<string>(type: "TEXT", nullable: true),
                    Suplementos = table.Column<string>(type: "TEXT", nullable: true),
                    Tabagismo = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    TipoDieta = table.Column<string>(type: "TEXT", maxLength: 30, nullable: true)
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

            migrationBuilder.UpdateData(
                table: "ConfiguracaoClinica",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataAtualizacao",
                value: new DateTime(2025, 10, 12, 16, 47, 40, 795, DateTimeKind.Utc).AddTicks(2164));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 12, 16, 47, 40, 795, DateTimeKind.Utc).AddTicks(1223));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 27, 16, 47, 40, 795, DateTimeKind.Utc).AddTicks(1244));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 10, 5, 16, 47, 40, 795, DateTimeKind.Utc).AddTicks(1251));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 12, 17, 47, 40, 795, DateTimeKind.Local).AddTicks(1868), new DateTime(2025, 9, 12, 17, 47, 40, 795, DateTimeKind.Local).AddTicks(1840) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 19, 17, 47, 40, 795, DateTimeKind.Local).AddTicks(1887), new DateTime(2025, 9, 19, 17, 47, 40, 795, DateTimeKind.Local).AddTicks(1880) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 2, 17, 47, 40, 795, DateTimeKind.Local).AddTicks(1901), new DateTime(2025, 10, 2, 17, 47, 40, 795, DateTimeKind.Local).AddTicks(1896) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 27, 17, 47, 40, 795, DateTimeKind.Local).AddTicks(1957), new DateTime(2025, 9, 27, 17, 47, 40, 795, DateTimeKind.Local).AddTicks(1922) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 11, 17, 47, 40, 795, DateTimeKind.Local).AddTicks(1969), new DateTime(2025, 10, 11, 17, 47, 40, 795, DateTimeKind.Local).AddTicks(1965) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 7, 17, 47, 40, 795, DateTimeKind.Local).AddTicks(1992), new DateTime(2025, 10, 7, 17, 47, 40, 795, DateTimeKind.Local).AddTicks(1987) });

            migrationBuilder.CreateIndex(
                name: "IX_HistoricosMedicos_PacienteId",
                table: "HistoricosMedicos",
                column: "PacienteId");
        }
    }
}
