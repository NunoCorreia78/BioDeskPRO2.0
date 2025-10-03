using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BioDesk.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddIrisdiagnosticoTables : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "IrisImagens",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    PacienteId = table.Column<int>(type: "INTEGER", nullable: false),
                    Olho = table.Column<string>(type: "TEXT", nullable: false),
                    DataCaptura = table.Column<DateTime>(type: "TEXT", nullable: false),
                    CaminhoImagem = table.Column<string>(type: "TEXT", nullable: false),
                    Observacoes = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IrisImagens", x => x.Id);
                    table.ForeignKey(
                        name: "FK_IrisImagens_Pacientes_PacienteId",
                        column: x => x.PacienteId,
                        principalTable: "Pacientes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "IrisMarcas",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    IrisImagemId = table.Column<int>(type: "INTEGER", nullable: false),
                    X = table.Column<double>(type: "REAL", nullable: false),
                    Y = table.Column<double>(type: "REAL", nullable: false),
                    Tipo = table.Column<string>(type: "TEXT", nullable: false),
                    Observacoes = table.Column<string>(type: "TEXT", nullable: true),
                    DataCriacao = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IrisMarcas", x => x.Id);
                    table.ForeignKey(
                        name: "FK_IrisMarcas_IrisImagens_IrisImagemId",
                        column: x => x.IrisImagemId,
                        principalTable: "IrisImagens",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 2, 16, 17, 21, 896, DateTimeKind.Utc).AddTicks(9542));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 17, 16, 17, 21, 896, DateTimeKind.Utc).AddTicks(9554));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 25, 16, 17, 21, 896, DateTimeKind.Utc).AddTicks(9560));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 2, 17, 17, 21, 897, DateTimeKind.Local).AddTicks(870), new DateTime(2025, 9, 2, 17, 17, 21, 897, DateTimeKind.Local).AddTicks(856) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 9, 17, 17, 21, 897, DateTimeKind.Local).AddTicks(893), new DateTime(2025, 9, 9, 17, 17, 21, 897, DateTimeKind.Local).AddTicks(878) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 22, 17, 17, 21, 897, DateTimeKind.Local).AddTicks(917), new DateTime(2025, 9, 22, 17, 17, 21, 897, DateTimeKind.Local).AddTicks(913) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 17, 17, 17, 21, 897, DateTimeKind.Local).AddTicks(947), new DateTime(2025, 9, 17, 17, 17, 21, 897, DateTimeKind.Local).AddTicks(936) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 1, 17, 17, 21, 897, DateTimeKind.Local).AddTicks(960), new DateTime(2025, 10, 1, 17, 17, 21, 897, DateTimeKind.Local).AddTicks(955) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 27, 17, 17, 21, 897, DateTimeKind.Local).AddTicks(999), new DateTime(2025, 9, 27, 17, 17, 21, 897, DateTimeKind.Local).AddTicks(993) });

            migrationBuilder.CreateIndex(
                name: "IX_IrisImagens_DataCaptura",
                table: "IrisImagens",
                column: "DataCaptura");

            migrationBuilder.CreateIndex(
                name: "IX_IrisImagens_PacienteId",
                table: "IrisImagens",
                column: "PacienteId");

            migrationBuilder.CreateIndex(
                name: "IX_IrisMarcas_IrisImagemId",
                table: "IrisMarcas",
                column: "IrisImagemId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "IrisMarcas");

            migrationBuilder.DropTable(
                name: "IrisImagens");

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 2, 15, 40, 44, 844, DateTimeKind.Utc).AddTicks(7955));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 17, 15, 40, 44, 844, DateTimeKind.Utc).AddTicks(7966));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 25, 15, 40, 44, 844, DateTimeKind.Utc).AddTicks(7971));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 2, 16, 40, 44, 844, DateTimeKind.Local).AddTicks(8468), new DateTime(2025, 9, 2, 16, 40, 44, 844, DateTimeKind.Local).AddTicks(8458) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 9, 16, 40, 44, 844, DateTimeKind.Local).AddTicks(8479), new DateTime(2025, 9, 9, 16, 40, 44, 844, DateTimeKind.Local).AddTicks(8475) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 22, 16, 40, 44, 844, DateTimeKind.Local).AddTicks(8491), new DateTime(2025, 9, 22, 16, 40, 44, 844, DateTimeKind.Local).AddTicks(8486) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 17, 16, 40, 44, 844, DateTimeKind.Local).AddTicks(8503), new DateTime(2025, 9, 17, 16, 40, 44, 844, DateTimeKind.Local).AddTicks(8497) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 1, 16, 40, 44, 844, DateTimeKind.Local).AddTicks(8514), new DateTime(2025, 10, 1, 16, 40, 44, 844, DateTimeKind.Local).AddTicks(8509) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 27, 16, 40, 44, 844, DateTimeKind.Local).AddTicks(8528), new DateTime(2025, 9, 27, 16, 40, 44, 844, DateTimeKind.Local).AddTicks(8520) });
        }
    }
}
