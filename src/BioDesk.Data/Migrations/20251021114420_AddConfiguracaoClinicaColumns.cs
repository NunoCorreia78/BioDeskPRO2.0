using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BioDesk.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddConfiguracaoClinicaColumns : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "ModoAplicacao",
                table: "SessionHistoricos",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<double>(
                name: "AlvoMelhoriaPadraoPercent",
                table: "ConfiguracaoClinica",
                type: "REAL",
                nullable: false,
                defaultValue: 0.0);

            migrationBuilder.AddColumn<double>(
                name: "CorrenteMaxPadraoma",
                table: "ConfiguracaoClinica",
                type: "REAL",
                nullable: false,
                defaultValue: 0.0);

            migrationBuilder.AddColumn<int>(
                name: "DuracaoUniformePadraoSegundos",
                table: "ConfiguracaoClinica",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<bool>(
                name: "ModoInformacionalPadrao",
                table: "ConfiguracaoClinica",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<string>(
                name: "TerapiaBiofeedbackSettingsJson",
                table: "ConfiguracaoClinica",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TerapiaProgramasSettingsJson",
                table: "ConfiguracaoClinica",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TerapiaRessonantesSettingsJson",
                table: "ConfiguracaoClinica",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<double>(
                name: "VoltageemPadraoV",
                table: "ConfiguracaoClinica",
                type: "REAL",
                nullable: false,
                defaultValue: 0.0);

            migrationBuilder.UpdateData(
                table: "ConfiguracaoClinica",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "AlvoMelhoriaPadraoPercent", "CorrenteMaxPadraoma", "DataAtualizacao", "DuracaoUniformePadraoSegundos", "ModoInformacionalPadrao", "TerapiaBiofeedbackSettingsJson", "TerapiaProgramasSettingsJson", "TerapiaRessonantesSettingsJson", "VoltageemPadraoV" },
                values: new object[] { 95.0, 50.0, new DateTime(2025, 10, 21, 11, 44, 18, 62, DateTimeKind.Utc).AddTicks(625), 10, false, null, null, null, 5.0 });

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 21, 11, 44, 18, 62, DateTimeKind.Utc).AddTicks(121));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 10, 6, 11, 44, 18, 62, DateTimeKind.Utc).AddTicks(131));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 10, 14, 11, 44, 18, 62, DateTimeKind.Utc).AddTicks(134));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 21, 12, 44, 18, 62, DateTimeKind.Local).AddTicks(503), new DateTime(2025, 9, 21, 12, 44, 18, 62, DateTimeKind.Local).AddTicks(490) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 28, 12, 44, 18, 62, DateTimeKind.Local).AddTicks(510), new DateTime(2025, 9, 28, 12, 44, 18, 62, DateTimeKind.Local).AddTicks(508) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 11, 12, 44, 18, 62, DateTimeKind.Local).AddTicks(516), new DateTime(2025, 10, 11, 12, 44, 18, 62, DateTimeKind.Local).AddTicks(514) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 6, 12, 44, 18, 62, DateTimeKind.Local).AddTicks(522), new DateTime(2025, 10, 6, 12, 44, 18, 62, DateTimeKind.Local).AddTicks(519) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 20, 12, 44, 18, 62, DateTimeKind.Local).AddTicks(528), new DateTime(2025, 10, 20, 12, 44, 18, 62, DateTimeKind.Local).AddTicks(526) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 16, 12, 44, 18, 62, DateTimeKind.Local).AddTicks(534), new DateTime(2025, 10, 16, 12, 44, 18, 62, DateTimeKind.Local).AddTicks(531) });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ModoAplicacao",
                table: "SessionHistoricos");

            migrationBuilder.DropColumn(
                name: "AlvoMelhoriaPadraoPercent",
                table: "ConfiguracaoClinica");

            migrationBuilder.DropColumn(
                name: "CorrenteMaxPadraoma",
                table: "ConfiguracaoClinica");

            migrationBuilder.DropColumn(
                name: "DuracaoUniformePadraoSegundos",
                table: "ConfiguracaoClinica");

            migrationBuilder.DropColumn(
                name: "ModoInformacionalPadrao",
                table: "ConfiguracaoClinica");

            migrationBuilder.DropColumn(
                name: "TerapiaBiofeedbackSettingsJson",
                table: "ConfiguracaoClinica");

            migrationBuilder.DropColumn(
                name: "TerapiaProgramasSettingsJson",
                table: "ConfiguracaoClinica");

            migrationBuilder.DropColumn(
                name: "TerapiaRessonantesSettingsJson",
                table: "ConfiguracaoClinica");

            migrationBuilder.DropColumn(
                name: "VoltageemPadraoV",
                table: "ConfiguracaoClinica");

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
        }
    }
}
