using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BioDesk.Data.Migrations
{
    /// <inheritdoc />
    public partial class FixShadowForeignKeys : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_EventosHardware_SessoesTerapia_SessaoTerapiaId1",
                table: "EventosHardware");

            migrationBuilder.DropForeignKey(
                name: "FK_LeiturasBioenergeticas_SessoesTerapia_SessaoTerapiaId1",
                table: "LeiturasBioenergeticas");

            migrationBuilder.DropForeignKey(
                name: "FK_Terapias_ProtocolosTerapeuticos_ProtocoloTerapeuticoId1",
                table: "Terapias");

            migrationBuilder.DropIndex(
                name: "IX_Terapias_ProtocoloTerapeuticoId1",
                table: "Terapias");

            migrationBuilder.DropIndex(
                name: "IX_LeiturasBioenergeticas_SessaoTerapiaId1",
                table: "LeiturasBioenergeticas");

            migrationBuilder.DropIndex(
                name: "IX_EventosHardware_SessaoTerapiaId1",
                table: "EventosHardware");

            migrationBuilder.DropColumn(
                name: "ProtocoloTerapeuticoId1",
                table: "Terapias");

            migrationBuilder.DropColumn(
                name: "SessaoTerapiaId1",
                table: "LeiturasBioenergeticas");

            migrationBuilder.DropColumn(
                name: "SessaoTerapiaId1",
                table: "EventosHardware");

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

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "ProtocoloTerapeuticoId1",
                table: "Terapias",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "SessaoTerapiaId1",
                table: "LeiturasBioenergeticas",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "SessaoTerapiaId1",
                table: "EventosHardware",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.UpdateData(
                table: "ConfiguracaoClinica",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataAtualizacao",
                value: new DateTime(2025, 10, 13, 13, 24, 15, 937, DateTimeKind.Utc).AddTicks(5218));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 13, 13, 24, 15, 937, DateTimeKind.Utc).AddTicks(4362));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 28, 13, 24, 15, 937, DateTimeKind.Utc).AddTicks(4375));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 10, 6, 13, 24, 15, 937, DateTimeKind.Utc).AddTicks(4379));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 13, 14, 24, 15, 937, DateTimeKind.Local).AddTicks(5033), new DateTime(2025, 9, 13, 14, 24, 15, 937, DateTimeKind.Local).AddTicks(5021) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 20, 14, 24, 15, 937, DateTimeKind.Local).AddTicks(5041), new DateTime(2025, 9, 20, 14, 24, 15, 937, DateTimeKind.Local).AddTicks(5038) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 3, 14, 24, 15, 937, DateTimeKind.Local).AddTicks(5048), new DateTime(2025, 10, 3, 14, 24, 15, 937, DateTimeKind.Local).AddTicks(5045) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 28, 14, 24, 15, 937, DateTimeKind.Local).AddTicks(5056), new DateTime(2025, 9, 28, 14, 24, 15, 937, DateTimeKind.Local).AddTicks(5052) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 12, 14, 24, 15, 937, DateTimeKind.Local).AddTicks(5063), new DateTime(2025, 10, 12, 14, 24, 15, 937, DateTimeKind.Local).AddTicks(5060) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 8, 14, 24, 15, 937, DateTimeKind.Local).AddTicks(5070), new DateTime(2025, 10, 8, 14, 24, 15, 937, DateTimeKind.Local).AddTicks(5066) });

            migrationBuilder.CreateIndex(
                name: "IX_Terapias_ProtocoloTerapeuticoId1",
                table: "Terapias",
                column: "ProtocoloTerapeuticoId1");

            migrationBuilder.CreateIndex(
                name: "IX_LeiturasBioenergeticas_SessaoTerapiaId1",
                table: "LeiturasBioenergeticas",
                column: "SessaoTerapiaId1");

            migrationBuilder.CreateIndex(
                name: "IX_EventosHardware_SessaoTerapiaId1",
                table: "EventosHardware",
                column: "SessaoTerapiaId1");

            migrationBuilder.AddForeignKey(
                name: "FK_EventosHardware_SessoesTerapia_SessaoTerapiaId1",
                table: "EventosHardware",
                column: "SessaoTerapiaId1",
                principalTable: "SessoesTerapia",
                principalColumn: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_LeiturasBioenergeticas_SessoesTerapia_SessaoTerapiaId1",
                table: "LeiturasBioenergeticas",
                column: "SessaoTerapiaId1",
                principalTable: "SessoesTerapia",
                principalColumn: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_Terapias_ProtocolosTerapeuticos_ProtocoloTerapeuticoId1",
                table: "Terapias",
                column: "ProtocoloTerapeuticoId1",
                principalTable: "ProtocolosTerapeuticos",
                principalColumn: "Id");
        }
    }
}
