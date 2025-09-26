using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace BioDesk.Data.Migrations
{
    /// <inheritdoc />
    public partial class AdicionarEntidadeConsulta : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Consultas",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    PacienteId = table.Column<int>(type: "INTEGER", nullable: false),
                    DataConsulta = table.Column<DateTime>(type: "TEXT", nullable: false),
                    TipoConsulta = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    Notas = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true),
                    Valor = table.Column<decimal>(type: "decimal(10,2)", nullable: true),
                    Status = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    DataCriacao = table.Column<DateTime>(type: "TEXT", nullable: false),
                    DataUltimaEdicao = table.Column<DateTime>(type: "TEXT", nullable: true)
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

            migrationBuilder.InsertData(
                table: "Consultas",
                columns: new[] { "Id", "DataConsulta", "DataCriacao", "DataUltimaEdicao", "Notas", "PacienteId", "Status", "TipoConsulta", "Valor" },
                values: new object[,]
                {
                    { 1, new DateTime(2025, 9, 11, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889), new DateTime(2025, 9, 11, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889), null, "Primeira consulta de naturopatia. Paciente apresenta sintomas de stress.", 1, "Realizada", "Primeira", 60.00m },
                    { 2, new DateTime(2025, 9, 18, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889), new DateTime(2025, 9, 18, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889), null, "Seguimento - melhoria dos sintomas de stress.", 1, "Realizada", "Seguimento", 45.00m },
                    { 3, new DateTime(2025, 9, 15, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889), new DateTime(2025, 9, 15, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889), null, "Primeira consulta de osteopatia. Dores lombares.", 2, "Realizada", "Primeira", 65.00m },
                    { 4, new DateTime(2025, 9, 27, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889), new DateTime(2025, 9, 22, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889), null, "Consulta agendada para medicina quântica.", 3, "Agendada", "Primeira", 70.00m }
                });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 23, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889), new DateTime(2025, 8, 26, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 20, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889), new DateTime(2025, 8, 31, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 24, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889), new DateTime(2025, 9, 5, 9, 58, 5, 187, DateTimeKind.Local).AddTicks(3889) });

            migrationBuilder.CreateIndex(
                name: "IX_Consulta_DataConsulta",
                table: "Consultas",
                column: "DataConsulta");

            migrationBuilder.CreateIndex(
                name: "IX_Consulta_PacienteId",
                table: "Consultas",
                column: "PacienteId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Consultas");

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 22, 17, 49, 22, 197, DateTimeKind.Local).AddTicks(8667), new DateTime(2025, 8, 25, 17, 49, 22, 197, DateTimeKind.Local).AddTicks(8667) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 19, 17, 49, 22, 197, DateTimeKind.Local).AddTicks(8667), new DateTime(2025, 8, 30, 17, 49, 22, 197, DateTimeKind.Local).AddTicks(8667) });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "AtualizadoEm", "CriadoEm" },
                values: new object[] { new DateTime(2025, 9, 23, 17, 49, 22, 197, DateTimeKind.Local).AddTicks(8667), new DateTime(2025, 9, 4, 17, 49, 22, 197, DateTimeKind.Local).AddTicks(8667) });
        }
    }
}
