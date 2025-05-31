using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecureDataSharing.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddDataPermissionsTable : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "DataPermissions",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    StoredDataId = table.Column<int>(type: "int", nullable: false),
                    OwnerUserId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    RecipientUserId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    GrantedTimestamp = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DataPermissions", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DataPermissions_AspNetUsers_OwnerUserId",
                        column: x => x.OwnerUserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_DataPermissions_AspNetUsers_RecipientUserId",
                        column: x => x.RecipientUserId,
                        principalTable: "AspNetUsers",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Restrict);
                    table.ForeignKey(
                        name: "FK_DataPermissions_StoredDatas_StoredDataId",
                        column: x => x.StoredDataId,
                        principalTable: "StoredDatas",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_DataPermissions_OwnerUserId",
                table: "DataPermissions",
                column: "OwnerUserId");

            migrationBuilder.CreateIndex(
                name: "IX_DataPermissions_RecipientUserId",
                table: "DataPermissions",
                column: "RecipientUserId");

            migrationBuilder.CreateIndex(
                name: "IX_DataPermissions_StoredDataId_RecipientUserId",
                table: "DataPermissions",
                columns: new[] { "StoredDataId", "RecipientUserId" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DataPermissions");
        }
    }
}
