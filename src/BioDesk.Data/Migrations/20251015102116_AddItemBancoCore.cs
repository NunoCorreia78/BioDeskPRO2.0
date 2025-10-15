using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BioDesk.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddItemBancoCore : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ItensBancoCore",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ExternalId = table.Column<Guid>(type: "TEXT", nullable: false),
                    Nome = table.Column<string>(type: "TEXT", maxLength: 300, nullable: false),
                    Categoria = table.Column<int>(type: "INTEGER", nullable: false),
                    Subcategoria = table.Column<string>(type: "TEXT", maxLength: 200, nullable: true),
                    DescricaoBreve = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    JsonMetadata = table.Column<string>(type: "TEXT", nullable: true),
                    FonteOrigem = table.Column<string>(type: "TEXT", maxLength: 300, nullable: true),
                    GeneroAplicavel = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    IsActive = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ItensBancoCore", x => x.Id);
                });

            migrationBuilder.UpdateData(
                table: "ConfiguracaoClinica",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataAtualizacao",
                value: new DateTime(2025, 10, 15, 10, 21, 13, 546, DateTimeKind.Utc).AddTicks(6338));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 15, 10, 21, 13, 546, DateTimeKind.Utc).AddTicks(5472));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 30, 10, 21, 13, 546, DateTimeKind.Utc).AddTicks(5488));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 10, 8, 10, 21, 13, 546, DateTimeKind.Utc).AddTicks(5493));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 15, 11, 21, 13, 546, DateTimeKind.Local).AddTicks(6094), new DateTime(2025, 9, 15, 11, 21, 13, 546, DateTimeKind.Local).AddTicks(6076) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 22, 11, 21, 13, 546, DateTimeKind.Local).AddTicks(6106), new DateTime(2025, 9, 22, 11, 21, 13, 546, DateTimeKind.Local).AddTicks(6102) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 5, 11, 21, 13, 546, DateTimeKind.Local).AddTicks(6117), new DateTime(2025, 10, 5, 11, 21, 13, 546, DateTimeKind.Local).AddTicks(6112) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 30, 11, 21, 13, 546, DateTimeKind.Local).AddTicks(6153), new DateTime(2025, 9, 30, 11, 21, 13, 546, DateTimeKind.Local).AddTicks(6131) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 14, 11, 21, 13, 546, DateTimeKind.Local).AddTicks(6164), new DateTime(2025, 10, 14, 11, 21, 13, 546, DateTimeKind.Local).AddTicks(6160) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 10, 11, 21, 13, 546, DateTimeKind.Local).AddTicks(6175), new DateTime(2025, 10, 10, 11, 21, 13, 546, DateTimeKind.Local).AddTicks(6169) });

            migrationBuilder.CreateIndex(
                name: "IX_ItensBancoCore_Categoria",
                table: "ItensBancoCore",
                column: "Categoria");

            migrationBuilder.CreateIndex(
                name: "IX_ItensBancoCore_Categoria_Active_Genero",
                table: "ItensBancoCore",
                columns: new[] { "Categoria", "IsActive", "GeneroAplicavel" });

            migrationBuilder.CreateIndex(
                name: "IX_ItensBancoCore_ExternalId",
                table: "ItensBancoCore",
                column: "ExternalId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ItensBancoCore_GeneroAplicavel",
                table: "ItensBancoCore",
                column: "GeneroAplicavel");

            migrationBuilder.CreateIndex(
                name: "IX_ItensBancoCore_IsActive",
                table: "ItensBancoCore",
                column: "IsActive");

            migrationBuilder.CreateIndex(
                name: "IX_ItensBancoCore_Nome",
                table: "ItensBancoCore",
                column: "Nome");

            migrationBuilder.CreateIndex(
                name: "IX_ItensBancoCore_Subcategoria",
                table: "ItensBancoCore",
                column: "Subcategoria");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ItensBancoCore");

            migrationBuilder.UpdateData(
                table: "ConfiguracaoClinica",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataAtualizacao",
                value: new DateTime(2025, 10, 13, 13, 39, 37, 581, DateTimeKind.Utc).AddTicks(3369));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 13, 13, 39, 37, 581, DateTimeKind.Utc).AddTicks(2912));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 28, 13, 39, 37, 581, DateTimeKind.Utc).AddTicks(2923));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 10, 6, 13, 39, 37, 581, DateTimeKind.Utc).AddTicks(2926));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 13, 14, 39, 37, 581, DateTimeKind.Local).AddTicks(3243), new DateTime(2025, 9, 13, 14, 39, 37, 581, DateTimeKind.Local).AddTicks(3232) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 20, 14, 39, 37, 581, DateTimeKind.Local).AddTicks(3251), new DateTime(2025, 9, 20, 14, 39, 37, 581, DateTimeKind.Local).AddTicks(3248) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 3, 14, 39, 37, 581, DateTimeKind.Local).AddTicks(3257), new DateTime(2025, 10, 3, 14, 39, 37, 581, DateTimeKind.Local).AddTicks(3254) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 28, 14, 39, 37, 581, DateTimeKind.Local).AddTicks(3263), new DateTime(2025, 9, 28, 14, 39, 37, 581, DateTimeKind.Local).AddTicks(3260) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 12, 14, 39, 37, 581, DateTimeKind.Local).AddTicks(3269), new DateTime(2025, 10, 12, 14, 39, 37, 581, DateTimeKind.Local).AddTicks(3267) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 8, 14, 39, 37, 581, DateTimeKind.Local).AddTicks(3275), new DateTime(2025, 10, 8, 14, 39, 37, 581, DateTimeKind.Local).AddTicks(3272) });
        }
    }
}
