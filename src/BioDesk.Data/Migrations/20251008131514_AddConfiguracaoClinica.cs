using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BioDesk.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddConfiguracaoClinica : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Comunicacoes_Pacientes_PacienteId",
                table: "Comunicacoes");

            migrationBuilder.DropForeignKey(
                name: "FK_IrisImagens_Pacientes_PacienteId",
                table: "IrisImagens");

            migrationBuilder.DropIndex(
                name: "IX_IrisImagens_DataCaptura",
                table: "IrisImagens");

            migrationBuilder.DropIndex(
                name: "IX_Comunicacoes_DataEnvio",
                table: "Comunicacoes");

            migrationBuilder.DropIndex(
                name: "IX_Comunicacoes_FilaRetry",
                table: "Comunicacoes");

            migrationBuilder.DropIndex(
                name: "IX_Comunicacoes_Status",
                table: "Comunicacoes");

            migrationBuilder.CreateTable(
                name: "ConfiguracaoClinica",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false),
                    NomeClinica = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    Morada = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    Telefone = table.Column<string>(type: "TEXT", maxLength: 50, nullable: true),
                    Email = table.Column<string>(type: "TEXT", maxLength: 100, nullable: true),
                    NIPC = table.Column<string>(type: "TEXT", maxLength: 20, nullable: true),
                    LogoPath = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true),
                    DataAtualizacao = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ConfiguracaoClinica", x => x.Id);
                });

            migrationBuilder.InsertData(
                table: "ConfiguracaoClinica",
                columns: new[] { "Id", "DataAtualizacao", "Email", "LogoPath", "Morada", "NIPC", "NomeClinica", "Telefone" },
                values: new object[] { 1, new DateTime(2025, 10, 8, 13, 15, 12, 850, DateTimeKind.Utc).AddTicks(4158), null, null, null, null, "Minha Clínica", null });

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

            migrationBuilder.AddForeignKey(
                name: "FK_Comunicacoes_Pacientes_PacienteId",
                table: "Comunicacoes",
                column: "PacienteId",
                principalTable: "Pacientes",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            migrationBuilder.AddForeignKey(
                name: "FK_IrisImagens_Pacientes_PacienteId",
                table: "IrisImagens",
                column: "PacienteId",
                principalTable: "Pacientes",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Comunicacoes_Pacientes_PacienteId",
                table: "Comunicacoes");

            migrationBuilder.DropForeignKey(
                name: "FK_IrisImagens_Pacientes_PacienteId",
                table: "IrisImagens");

            migrationBuilder.DropTable(
                name: "ConfiguracaoClinica");

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 8, 9, 24, 20, 865, DateTimeKind.Utc).AddTicks(1010));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 23, 9, 24, 20, 865, DateTimeKind.Utc).AddTicks(1021));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 10, 1, 9, 24, 20, 865, DateTimeKind.Utc).AddTicks(1024));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 8, 10, 24, 20, 865, DateTimeKind.Local).AddTicks(1412), new DateTime(2025, 9, 8, 10, 24, 20, 865, DateTimeKind.Local).AddTicks(1399) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 15, 10, 24, 20, 865, DateTimeKind.Local).AddTicks(1421), new DateTime(2025, 9, 15, 10, 24, 20, 865, DateTimeKind.Local).AddTicks(1418) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 28, 10, 24, 20, 865, DateTimeKind.Local).AddTicks(1426), new DateTime(2025, 9, 28, 10, 24, 20, 865, DateTimeKind.Local).AddTicks(1424) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 23, 10, 24, 20, 865, DateTimeKind.Local).AddTicks(1433), new DateTime(2025, 9, 23, 10, 24, 20, 865, DateTimeKind.Local).AddTicks(1430) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 7, 10, 24, 20, 865, DateTimeKind.Local).AddTicks(1438), new DateTime(2025, 10, 7, 10, 24, 20, 865, DateTimeKind.Local).AddTicks(1436) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 3, 10, 24, 20, 865, DateTimeKind.Local).AddTicks(1443), new DateTime(2025, 10, 3, 10, 24, 20, 865, DateTimeKind.Local).AddTicks(1441) });

            migrationBuilder.CreateIndex(
                name: "IX_IrisImagens_DataCaptura",
                table: "IrisImagens",
                column: "DataCaptura");

            migrationBuilder.CreateIndex(
                name: "IX_Comunicacoes_DataEnvio",
                table: "Comunicacoes",
                column: "DataEnvio");

            migrationBuilder.CreateIndex(
                name: "IX_Comunicacoes_FilaRetry",
                table: "Comunicacoes",
                columns: new[] { "IsEnviado", "ProximaTentativa" });

            migrationBuilder.CreateIndex(
                name: "IX_Comunicacoes_Status",
                table: "Comunicacoes",
                column: "Status");

            migrationBuilder.AddForeignKey(
                name: "FK_Comunicacoes_Pacientes_PacienteId",
                table: "Comunicacoes",
                column: "PacienteId",
                principalTable: "Pacientes",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);

            migrationBuilder.AddForeignKey(
                name: "FK_IrisImagens_Pacientes_PacienteId",
                table: "IrisImagens",
                column: "PacienteId",
                principalTable: "Pacientes",
                principalColumn: "Id",
                onDelete: ReferentialAction.Restrict);
        }
    }
}
