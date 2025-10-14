using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BioDesk.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddTerapiasBioenergeticas : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_SessoesTerapia_Estado",
                table: "SessoesTerapia");

            migrationBuilder.DropIndex(
                name: "IX_SessoesTerapia_InicioEm",
                table: "SessoesTerapia");

            migrationBuilder.DropIndex(
                name: "IX_SessoesTerapia_PlanoTerapiaId",
                table: "SessoesTerapia");

            migrationBuilder.DropIndex(
                name: "IX_ProtocolosTerapeuticos_Ativo",
                table: "ProtocolosTerapeuticos");

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
                name: "IX_SessoesTerapia_PlanoId_Inicio",
                table: "SessoesTerapia",
                columns: new[] { "PlanoTerapiaId", "InicioEm" });

            migrationBuilder.CreateIndex(
                name: "IX_SessoesTerapia_TipoRng",
                table: "SessoesTerapia",
                column: "TipoRng");

            migrationBuilder.CreateIndex(
                name: "IX_PlanosTerapia_CriadoEm",
                table: "PlanosTerapia",
                column: "CriadoEm");

            migrationBuilder.CreateIndex(
                name: "IX_PlanosTerapia_Estado",
                table: "PlanosTerapia",
                column: "Estado");

            migrationBuilder.CreateIndex(
                name: "IX_LeiturasBioenergeticas_SessaoTerapiaId1",
                table: "LeiturasBioenergeticas",
                column: "SessaoTerapiaId1");

            migrationBuilder.CreateIndex(
                name: "IX_EventosHardware_SessaoTerapiaId1",
                table: "EventosHardware",
                column: "SessaoTerapiaId1");

            migrationBuilder.CreateIndex(
                name: "IX_EventosHardware_Severidade",
                table: "EventosHardware",
                column: "Severidade");

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

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
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
                name: "IX_SessoesTerapia_PlanoId_Inicio",
                table: "SessoesTerapia");

            migrationBuilder.DropIndex(
                name: "IX_SessoesTerapia_TipoRng",
                table: "SessoesTerapia");

            migrationBuilder.DropIndex(
                name: "IX_PlanosTerapia_CriadoEm",
                table: "PlanosTerapia");

            migrationBuilder.DropIndex(
                name: "IX_PlanosTerapia_Estado",
                table: "PlanosTerapia");

            migrationBuilder.DropIndex(
                name: "IX_LeiturasBioenergeticas_SessaoTerapiaId1",
                table: "LeiturasBioenergeticas");

            migrationBuilder.DropIndex(
                name: "IX_EventosHardware_SessaoTerapiaId1",
                table: "EventosHardware");

            migrationBuilder.DropIndex(
                name: "IX_EventosHardware_Severidade",
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
                value: new DateTime(2025, 10, 12, 19, 39, 50, 268, DateTimeKind.Utc).AddTicks(6151));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 1,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 12, 19, 39, 50, 267, DateTimeKind.Utc).AddTicks(6455));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 2,
                column: "DataCriacao",
                value: new DateTime(2025, 9, 27, 19, 39, 50, 267, DateTimeKind.Utc).AddTicks(6470));

            migrationBuilder.UpdateData(
                table: "Pacientes",
                keyColumn: "Id",
                keyValue: 3,
                column: "DataCriacao",
                value: new DateTime(2025, 10, 5, 19, 39, 50, 267, DateTimeKind.Utc).AddTicks(6473));

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 1,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 12, 20, 39, 50, 267, DateTimeKind.Local).AddTicks(6790), new DateTime(2025, 9, 12, 20, 39, 50, 267, DateTimeKind.Local).AddTicks(6778) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 2,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 19, 20, 39, 50, 267, DateTimeKind.Local).AddTicks(6797), new DateTime(2025, 9, 19, 20, 39, 50, 267, DateTimeKind.Local).AddTicks(6794) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 3,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 2, 20, 39, 50, 267, DateTimeKind.Local).AddTicks(6804), new DateTime(2025, 10, 2, 20, 39, 50, 267, DateTimeKind.Local).AddTicks(6801) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 4,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 9, 27, 20, 39, 50, 267, DateTimeKind.Local).AddTicks(6874), new DateTime(2025, 9, 27, 20, 39, 50, 267, DateTimeKind.Local).AddTicks(6822) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 5,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 11, 20, 39, 50, 267, DateTimeKind.Local).AddTicks(6881), new DateTime(2025, 10, 11, 20, 39, 50, 267, DateTimeKind.Local).AddTicks(6878) });

            migrationBuilder.UpdateData(
                table: "Sessoes",
                keyColumn: "Id",
                keyValue: 6,
                columns: new[] { "CriadoEm", "DataHora" },
                values: new object[] { new DateTime(2025, 10, 7, 20, 39, 50, 267, DateTimeKind.Local).AddTicks(6887), new DateTime(2025, 10, 7, 20, 39, 50, 267, DateTimeKind.Local).AddTicks(6884) });

            migrationBuilder.CreateIndex(
                name: "IX_SessoesTerapia_Estado",
                table: "SessoesTerapia",
                column: "Estado");

            migrationBuilder.CreateIndex(
                name: "IX_SessoesTerapia_InicioEm",
                table: "SessoesTerapia",
                column: "InicioEm");

            migrationBuilder.CreateIndex(
                name: "IX_SessoesTerapia_PlanoTerapiaId",
                table: "SessoesTerapia",
                column: "PlanoTerapiaId");

            migrationBuilder.CreateIndex(
                name: "IX_ProtocolosTerapeuticos_Ativo",
                table: "ProtocolosTerapeuticos",
                column: "Ativo");
        }
    }
}
