using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BioDesk.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddTemplatesAndExternalDocuments : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "DocumentosExternosPacientes",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    PacienteId = table.Column<int>(type: "INTEGER", nullable: false),
                    NomeArquivo = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    CaminhoArquivo = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    Descricao = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    DataDocumento = table.Column<DateTime>(type: "TEXT", nullable: true),
                    Categoria = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    DataUpload = table.Column<DateTime>(type: "TEXT", nullable: false),
                    TamanhoBytes = table.Column<long>(type: "INTEGER", nullable: true),
                    TipoMime = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    IsDeleted = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DocumentosExternosPacientes", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DocumentosExternosPacientes_Pacientes_PacienteId",
                        column: x => x.PacienteId,
                        principalTable: "Pacientes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "TemplatesGlobais",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Nome = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Tipo = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    CaminhoArquivo = table.Column<string>(type: "TEXT", maxLength: 500, nullable: false),
                    Descricao = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    DisponivelEmail = table.Column<bool>(type: "INTEGER", nullable: false),
                    Categoria = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    DataAdicao = table.Column<DateTime>(type: "TEXT", nullable: false),
                    DataAtualizacao = table.Column<DateTime>(type: "TEXT", nullable: true),
                    IsDeleted = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TemplatesGlobais", x => x.Id);
                });

            migrationBuilder.UpdateData(
                table: "ConfiguracaoClinica",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataAtualizacao",
                value: new DateTime(2025, 10, 9, 11, 22, 5, 862, DateTimeKind.Utc).AddTicks(8724));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 9, 11, 22, 5, 862, DateTimeKind.Utc).AddTicks(8204));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 24, 11, 22, 5, 862, DateTimeKind.Utc).AddTicks(8220));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 10, 2, 11, 22, 5, 862, DateTimeKind.Utc).AddTicks(8223));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 9, 12, 22, 5, 862, DateTimeKind.Local).AddTicks(8546), new DateTime(2025, 9, 9, 12, 22, 5, 862, DateTimeKind.Local).AddTicks(8533) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 16, 12, 22, 5, 862, DateTimeKind.Local).AddTicks(8555), new DateTime(2025, 9, 16, 12, 22, 5, 862, DateTimeKind.Local).AddTicks(8551) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 29, 12, 22, 5, 862, DateTimeKind.Local).AddTicks(8561), new DateTime(2025, 9, 29, 12, 22, 5, 862, DateTimeKind.Local).AddTicks(8559) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 24, 12, 22, 5, 862, DateTimeKind.Local).AddTicks(8612), new DateTime(2025, 9, 24, 12, 22, 5, 862, DateTimeKind.Local).AddTicks(8585) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 8, 12, 22, 5, 862, DateTimeKind.Local).AddTicks(8619), new DateTime(2025, 10, 8, 12, 22, 5, 862, DateTimeKind.Local).AddTicks(8616) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 4, 12, 22, 5, 862, DateTimeKind.Local).AddTicks(8626), new DateTime(2025, 10, 4, 12, 22, 5, 862, DateTimeKind.Local).AddTicks(8623) });

            migrationBuilder.CreateIndex(
                name: "IX_DocumentosExternos_Categoria",
                table: "DocumentosExternosPacientes",
                column: "Categoria");

            migrationBuilder.CreateIndex(
                name: "IX_DocumentosExternos_DataDocumento",
                table: "DocumentosExternosPacientes",
                column: "DataDocumento");

            migrationBuilder.CreateIndex(
                name: "IX_DocumentosExternos_IsDeleted",
                table: "DocumentosExternosPacientes",
                column: "IsDeleted");

            migrationBuilder.CreateIndex(
                name: "IX_DocumentosExternos_PacienteId",
                table: "DocumentosExternosPacientes",
                column: "PacienteId");

            migrationBuilder.CreateIndex(
                name: "IX_TemplatesGlobais_Categoria",
                table: "TemplatesGlobais",
                column: "Categoria");

            migrationBuilder.CreateIndex(
                name: "IX_TemplatesGlobais_DisponivelEmail",
                table: "TemplatesGlobais",
                column: "DisponivelEmail");

            migrationBuilder.CreateIndex(
                name: "IX_TemplatesGlobais_IsDeleted",
                table: "TemplatesGlobais",
                column: "IsDeleted");

            migrationBuilder.CreateIndex(
                name: "IX_TemplatesGlobais_Nome",
                table: "TemplatesGlobais",
                column: "Nome");

            migrationBuilder.CreateIndex(
                name: "IX_TemplatesGlobais_Tipo",
                table: "TemplatesGlobais",
                column: "Tipo");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DocumentosExternosPacientes");

            migrationBuilder.DropTable(
                name: "TemplatesGlobais");

            migrationBuilder.UpdateData(
                table: "ConfiguracaoClinica",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataAtualizacao",
                value: new DateTime(2025, 10, 8, 13, 15, 12, 850, DateTimeKind.Utc).AddTicks(4158));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 8, 13, 15, 12, 850, DateTimeKind.Utc).AddTicks(3767));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 23, 13, 15, 12, 850, DateTimeKind.Utc).AddTicks(3777));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 10, 1, 13, 15, 12, 850, DateTimeKind.Utc).AddTicks(3780));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 8, 14, 15, 12, 850, DateTimeKind.Local).AddTicks(4056), new DateTime(2025, 9, 8, 14, 15, 12, 850, DateTimeKind.Local).AddTicks(4042) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 15, 14, 15, 12, 850, DateTimeKind.Local).AddTicks(4063), new DateTime(2025, 9, 15, 14, 15, 12, 850, DateTimeKind.Local).AddTicks(4061) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 28, 14, 15, 12, 850, DateTimeKind.Local).AddTicks(4068), new DateTime(2025, 9, 28, 14, 15, 12, 850, DateTimeKind.Local).AddTicks(4066) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 23, 14, 15, 12, 850, DateTimeKind.Local).AddTicks(4073), new DateTime(2025, 9, 23, 14, 15, 12, 850, DateTimeKind.Local).AddTicks(4071) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 7, 14, 15, 12, 850, DateTimeKind.Local).AddTicks(4078), new DateTime(2025, 10, 7, 14, 15, 12, 850, DateTimeKind.Local).AddTicks(4076) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 3, 14, 15, 12, 850, DateTimeKind.Local).AddTicks(4083), new DateTime(2025, 10, 3, 14, 15, 12, 850, DateTimeKind.Local).AddTicks(4081) });
        }
    }
}
