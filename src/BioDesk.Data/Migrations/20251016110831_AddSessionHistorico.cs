using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BioDesk.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddSessionHistorico : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "SessionHistoricos",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    PacienteId = table.Column<int>(type: "INTEGER", nullable: true),
                    DataHoraInicio = table.Column<DateTime>(type: "TEXT", nullable: false),
                    TipoTerapia = table.Column<int>(type: "INTEGER", nullable: false),
                    ProtocolosJson = table.Column<string>(type: "TEXT", nullable: false),
                    FrequenciasHzJson = table.Column<string>(type: "TEXT", nullable: false),
                    DuracaoMinutos = table.Column<int>(type: "INTEGER", nullable: true),
                    VoltagemV = table.Column<double>(type: "REAL", nullable: true),
                    CorrenteMa = table.Column<double>(type: "REAL", nullable: true),
                    Notas = table.Column<string>(type: "TEXT", nullable: true),
                    CriadoEm = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SessionHistoricos", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SessionHistoricos_Pacientes_PacienteId",
                        column: x => x.PacienteId,
                        principalTable: "Pacientes",
                        principalColumn: "Id");
                });

            migrationBuilder.UpdateData(
                table: "ConfiguracaoClinica",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataAtualizacao",
                value: new DateTime(2025, 10, 16, 11, 8, 27, 484, DateTimeKind.Utc).AddTicks(9122));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 16, 11, 8, 27, 484, DateTimeKind.Utc).AddTicks(7841));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 10, 1, 11, 8, 27, 484, DateTimeKind.Utc).AddTicks(7877));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 10, 9, 11, 8, 27, 484, DateTimeKind.Utc).AddTicks(7885));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 16, 12, 8, 27, 484, DateTimeKind.Local).AddTicks(8835), new DateTime(2025, 9, 16, 12, 8, 27, 484, DateTimeKind.Local).AddTicks(8815) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 23, 12, 8, 27, 484, DateTimeKind.Local).AddTicks(8848), new DateTime(2025, 9, 23, 12, 8, 27, 484, DateTimeKind.Local).AddTicks(8843) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 6, 12, 8, 27, 484, DateTimeKind.Local).AddTicks(8862), new DateTime(2025, 10, 6, 12, 8, 27, 484, DateTimeKind.Local).AddTicks(8857) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 1, 12, 8, 27, 484, DateTimeKind.Local).AddTicks(8934), new DateTime(2025, 10, 1, 12, 8, 27, 484, DateTimeKind.Local).AddTicks(8890) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 15, 12, 8, 27, 484, DateTimeKind.Local).AddTicks(8948), new DateTime(2025, 10, 15, 12, 8, 27, 484, DateTimeKind.Local).AddTicks(8943) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 11, 12, 8, 27, 484, DateTimeKind.Local).AddTicks(8961), new DateTime(2025, 10, 11, 12, 8, 27, 484, DateTimeKind.Local).AddTicks(8955) });

            migrationBuilder.CreateIndex(
                name: "IX_SessionHistoricos_PacienteId",
                table: "SessionHistoricos",
                column: "PacienteId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "SessionHistoricos");

            migrationBuilder.UpdateData(
                table: "ConfiguracaoClinica",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataAtualizacao",
                value: new DateTime(2025, 10, 15, 10, 26, 11, 752, DateTimeKind.Utc).AddTicks(6825));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 15, 10, 26, 11, 752, DateTimeKind.Utc).AddTicks(6037));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 30, 10, 26, 11, 752, DateTimeKind.Utc).AddTicks(6049));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 10, 8, 10, 26, 11, 752, DateTimeKind.Utc).AddTicks(6055));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 15, 11, 26, 11, 752, DateTimeKind.Local).AddTicks(6579), new DateTime(2025, 9, 15, 11, 26, 11, 752, DateTimeKind.Local).AddTicks(6562) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 22, 11, 26, 11, 752, DateTimeKind.Local).AddTicks(6590), new DateTime(2025, 9, 22, 11, 26, 11, 752, DateTimeKind.Local).AddTicks(6586) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 5, 11, 26, 11, 752, DateTimeKind.Local).AddTicks(6600), new DateTime(2025, 10, 5, 11, 26, 11, 752, DateTimeKind.Local).AddTicks(6596) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 30, 11, 26, 11, 752, DateTimeKind.Local).AddTicks(6660), new DateTime(2025, 9, 30, 11, 26, 11, 752, DateTimeKind.Local).AddTicks(6616) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 14, 11, 26, 11, 752, DateTimeKind.Local).AddTicks(6670), new DateTime(2025, 10, 14, 11, 26, 11, 752, DateTimeKind.Local).AddTicks(6667) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 10, 11, 26, 11, 752, DateTimeKind.Local).AddTicks(6680), new DateTime(2025, 10, 10, 11, 26, 11, 752, DateTimeKind.Local).AddTicks(6676) });
        }
    }
}
