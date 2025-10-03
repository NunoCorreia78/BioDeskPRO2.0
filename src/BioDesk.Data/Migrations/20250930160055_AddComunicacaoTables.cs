using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BioDesk.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddComunicacaoTables : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Comunicacoes",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    PacienteId = table.Column<int>(type: "INTEGER", nullable: false),
                    Tipo = table.Column<int>(type: "INTEGER", nullable: false),
                    Destinatario = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Assunto = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    Corpo = table.Column<string>(type: "TEXT", nullable: false),
                    TemplateUtilizado = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    Status = table.Column<int>(type: "INTEGER", nullable: false),
                    DataCriacao = table.Column<DateTime>(type: "TEXT", nullable: false),
                    DataEnvio = table.Column<DateTime>(type: "TEXT", nullable: true),
                    DataAbertura = table.Column<DateTime>(type: "TEXT", nullable: true),
                    FoiAberto = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsEnviado = table.Column<bool>(type: "INTEGER", nullable: false),
                    TentativasEnvio = table.Column<int>(type: "INTEGER", nullable: false),
                    ProximaTentativa = table.Column<DateTime>(type: "TEXT", nullable: true),
                    UltimoErro = table.Column<string>(type: "TEXT", maxLength: 1000, nullable: true),
                    DataFollowUp = table.Column<DateTime>(type: "TEXT", nullable: true),
                    MensagemFollowUp = table.Column<string>(type: "TEXT", nullable: true),
                    FollowUpEnviado = table.Column<bool>(type: "INTEGER", nullable: false),
                    Observacoes = table.Column<string>(type: "TEXT", nullable: true),
                    IsDeleted = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Comunicacoes", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Comunicacoes_Pacientes_PacienteId",
                        column: x => x.PacienteId,
                        principalTable: "Pacientes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateTable(
                name: "AnexosComunicacoes",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ComunicacaoId = table.Column<int>(type: "INTEGER", nullable: false),
                    NomeArquivo = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    CaminhoArquivo = table.Column<string>(type: "TEXT", nullable: false),
                    TipoMime = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    TamanhoBytes = table.Column<long>(type: "INTEGER", nullable: false),
                    DataCriacao = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AnexosComunicacoes", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AnexosComunicacoes_Comunicacoes_ComunicacaoId",
                        column: x => x.ComunicacaoId,
                        principalTable: "Comunicacoes",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 8, 31, 16, 0, 53, 894, DateTimeKind.Utc).AddTicks(1352));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 15, 16, 0, 53, 894, DateTimeKind.Utc).AddTicks(1362));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 23, 16, 0, 53, 894, DateTimeKind.Utc).AddTicks(1366));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 8, 31, 17, 0, 53, 894, DateTimeKind.Local).AddTicks(1655), new DateTime(2025, 8, 31, 17, 0, 53, 894, DateTimeKind.Local).AddTicks(1646) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 7, 17, 0, 53, 894, DateTimeKind.Local).AddTicks(1663), new DateTime(2025, 9, 7, 17, 0, 53, 894, DateTimeKind.Local).AddTicks(1659) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 20, 17, 0, 53, 894, DateTimeKind.Local).AddTicks(1674), new DateTime(2025, 9, 20, 17, 0, 53, 894, DateTimeKind.Local).AddTicks(1667) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 15, 17, 0, 53, 894, DateTimeKind.Local).AddTicks(1682), new DateTime(2025, 9, 15, 17, 0, 53, 894, DateTimeKind.Local).AddTicks(1678) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 29, 17, 0, 53, 894, DateTimeKind.Local).AddTicks(1688), new DateTime(2025, 9, 29, 17, 0, 53, 894, DateTimeKind.Local).AddTicks(1685) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 25, 17, 0, 53, 894, DateTimeKind.Local).AddTicks(1742), new DateTime(2025, 9, 25, 17, 0, 53, 894, DateTimeKind.Local).AddTicks(1738) });

            migrationBuilder.CreateIndex(
                name: "IX_AnexosComunicacoes_ComunicacaoId",
                table: "AnexosComunicacoes",
                column: "ComunicacaoId");

            migrationBuilder.CreateIndex(
                name: "IX_Comunicacoes_DataEnvio",
                table: "Comunicacoes",
                column: "DataEnvio");

            migrationBuilder.CreateIndex(
                name: "IX_Comunicacoes_FilaRetry",
                table: "Comunicacoes",
                columns: new[] { "IsEnviado", "ProximaTentativa" });

            migrationBuilder.CreateIndex(
                name: "IX_Comunicacoes_PacienteId",
                table: "Comunicacoes",
                column: "PacienteId");

            migrationBuilder.CreateIndex(
                name: "IX_Comunicacoes_Status",
                table: "Comunicacoes",
                column: "Status");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AnexosComunicacoes");

            migrationBuilder.DropTable(
                name: "Comunicacoes");

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 8, 31, 11, 44, 21, 27, DateTimeKind.Utc).AddTicks(6827));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 15, 11, 44, 21, 27, DateTimeKind.Utc).AddTicks(6838));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 23, 11, 44, 21, 27, DateTimeKind.Utc).AddTicks(6843));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 8, 31, 12, 44, 21, 27, DateTimeKind.Local).AddTicks(7110), new DateTime(2025, 8, 31, 12, 44, 21, 27, DateTimeKind.Local).AddTicks(7098) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 7, 12, 44, 21, 27, DateTimeKind.Local).AddTicks(7121), new DateTime(2025, 9, 7, 12, 44, 21, 27, DateTimeKind.Local).AddTicks(7116) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 20, 12, 44, 21, 27, DateTimeKind.Local).AddTicks(7141), new DateTime(2025, 9, 20, 12, 44, 21, 27, DateTimeKind.Local).AddTicks(7137) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 15, 12, 44, 21, 27, DateTimeKind.Local).AddTicks(7152), new DateTime(2025, 9, 15, 12, 44, 21, 27, DateTimeKind.Local).AddTicks(7147) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 29, 12, 44, 21, 27, DateTimeKind.Local).AddTicks(7162), new DateTime(2025, 9, 29, 12, 44, 21, 27, DateTimeKind.Local).AddTicks(7158) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 25, 12, 44, 21, 27, DateTimeKind.Local).AddTicks(7173), new DateTime(2025, 9, 25, 12, 44, 21, 27, DateTimeKind.Local).AddTicks(7168) });
        }
    }
}
