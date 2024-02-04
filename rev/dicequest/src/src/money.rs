use crate::animated_sprite::AnimatedSpriteBundle;
use crate::{
    Cooldown, Damage, Death, GameState, Health, OwnedItems, Player, PLAYER_ATTACK_COOLDOWN,
    PLAYER_DAMAGE_INITIAL, PLAYER_HEALTH_INITIAL, PLAYER_REGEN_TIMER_INITIAL, PLAYER_SIZE,
};
use bevy::prelude::*;
use bevy::sprite::collide_aabb::collide;
use std::fmt::Formatter;
use std::time::Duration;

use crate::regen::RegenCooldown;
#[cfg(feature = "inspect")]
use bevy_inspector_egui::prelude::*;

const SHOPKEEP_SIZE: Vec2 = Vec2::new(128., 130.);

pub struct MoneyPlugin;

const ACTIVE_SHOP_BUTTON_COLOR: &str = "#dea95f";
const INACTIVE_SHOP_BUTTON_COLOR: &str = "#96866f";

#[derive(Component, Default)]
#[cfg_attr(feature = "inspect", derive(Reflect, InspectorOptions))]
#[cfg_attr(feature = "inspect", reflect(Component, InspectorOptions))]
pub struct Coins(pub u32);

#[derive(Component)]
pub struct KillReward(pub u32);

#[derive(Component)]
struct MoneyText;

#[derive(Component)]
struct ShopKeep(Vec<ShopItem>);

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ShopItem {
    DualWield,
    TameDragon,
    HealthIncrease,
    DamageIncrease,
    RegenIncrease,
}

impl std::fmt::Display for ShopItem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl ShopItem {
    pub fn name(&self) -> &'static str {
        match self {
            ShopItem::DualWield => "Dual Wielding",
            ShopItem::TameDragon => "Tame Dragon",
            ShopItem::HealthIncrease => "Double Health",
            ShopItem::DamageIncrease => "Damage Increase",
            ShopItem::RegenIncrease => "Regen Increase",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            ShopItem::DualWield => "Wield two swords, reducing attack cooldown",
            ShopItem::TameDragon => "Tame the dragon army",
            ShopItem::HealthIncrease => "Doubles your maximum health capacity",
            ShopItem::DamageIncrease => "Doubles the damage of your sword",
            ShopItem::RegenIncrease => "Doubles the rate at which you regenerate health",
        }
    }

    pub fn price(&self) -> u32 {
        match self {
            ShopItem::DualWield => 5,
            ShopItem::TameDragon => 10000,
            ShopItem::HealthIncrease => 100,
            ShopItem::DamageIncrease => 100,
            ShopItem::RegenIncrease => 100,
        }
    }

    pub fn all() -> [Self; 5] {
        [
            Self::DualWield,
            Self::TameDragon,
            Self::HealthIncrease,
            Self::DamageIncrease,
            Self::RegenIncrease,
        ]
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Default, States)]
enum ShopState {
    #[default]
    Closed,
    Open,
    /// The window was just closed, don't reopen shopkeep window until we leave
    /// the shopkeepers hitbox
    JustClosed,
}

impl Plugin for MoneyPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(Startup, (spawn_money_counter, spawn_shopkeep))
            .add_systems(
                Update,
                (
                    give_kill_rewards,
                    update_money_text,
                    shopkeep_collision.run_if(in_state(GameState::Running)),
                    shop_action.run_if(in_state(ShopState::Open)),
                ),
            )
            .add_systems(OnEnter(ShopState::Open), open_shop)
            .add_systems(OnExit(ShopState::Open), close_shop)
            .add_state::<ShopState>();
    }
}

fn spawn_money_counter(mut commands: Commands) {
    let container = NodeBundle {
        style: Style {
            width: Val::Px(300.0),
            height: Val::Px(200.0),
            border: UiRect::all(Val::Px(2.0)),
            ..default()
        },
        background_color: Color::rgba(0.0, 0.0, 0., 0.).into(),
        ..default()
    };
    let text = TextBundle::from_section(
        "0",
        TextStyle {
            font_size: 100.0,
            color: Color::WHITE,
            ..default()
        },
    )
    .with_text_alignment(TextAlignment::Left);
    let container = commands.spawn(container).id();
    let text = commands.spawn((text, MoneyText)).id();
    commands.entity(container).push_children(&[text]);
}

fn spawn_shopkeep(
    mut commands: Commands,
    asset_server: Res<AssetServer>,
    mut texture_atlases: ResMut<Assets<TextureAtlas>>,
) {
    commands.spawn((
        ShopKeep(ShopItem::all().to_vec()),
        AnimatedSpriteBundle::new(
            asset_server.load("gin.png"),
            Vec2::new(64.0, 66.0),
            8,
            1,
            texture_atlases.as_mut(),
        )
        .with_transform(
            Transform::from_translation(Vec3::new(300.0, 200.0, 0.0))
                .with_scale(Vec3::new(2.0, 2.0, 0.0)),
        ),
    ));
}

#[derive(Component)]
struct ShopWindow;

#[derive(Component, Debug)]
enum ShopButtonAction {
    Buy(ShopItem),
    Quit,
}

fn open_shop(
    mut commands: Commands,
    shop_keep: Query<&ShopKeep>,
    owned_items: Query<&OwnedItems, With<Player>>,
) {
    let shop_keep = shop_keep.single();
    let owned_items = owned_items.single();
    let mut window = commands.spawn((
        NodeBundle {
            style: Style {
                align_items: AlignItems::Start,
                justify_content: JustifyContent::Center,
                display: Display::Grid,
                align_self: AlignSelf::Center,
                justify_self: JustifySelf::Center,
                width: Val::Percent(85.0),
                height: Val::Percent(90.0),
                padding: UiRect {
                    top: Val::Px(20.0),
                    left: Val::Px(30.0),
                    right: Val::Px(30.0),
                    ..default()
                },
                ..default()
            },
            background_color: Color::hex("#ebbf81").unwrap().into(),
            ..default()
        },
        ShopWindow,
    ));
    window.with_children(|window| {
        // spawn item boxes
        for &item in &shop_keep.0 {
            let background_color = if owned_items.0.contains(&item) {
                Color::hex(INACTIVE_SHOP_BUTTON_COLOR).unwrap().into()
            } else {
                Color::hex(ACTIVE_SHOP_BUTTON_COLOR).unwrap().into()
            };
            let mut button = window.spawn((
                ButtonBundle {
                    style: Style {
                        height: Val::Px(200.0),
                        width: Val::Percent(40.0),
                        padding: UiRect::all(Val::Px(10.0)),
                        ..default()
                    },
                    background_color,
                    ..default()
                },
                ShopButtonAction::Buy(item),
            ));
            button.with_children(|shop_item| {
                let name = format!("{}\n", item.name());
                let description = format!("{}\n", item.description());
                let price = format!("${}", item.price());
                let text1 = TextBundle::from_sections([
                    TextSection::new(
                        name,
                        TextStyle {
                            font_size: 40.0,
                            ..default()
                        },
                    ),
                    TextSection::new(
                        description,
                        TextStyle {
                            font_size: 26.0,
                            ..default()
                        },
                    ),
                ]);
                let text2 = TextBundle::from_section(
                    price,
                    TextStyle {
                        font_size: 30.0,
                        color: Color::DARK_GREEN,
                        ..default()
                    },
                )
                .with_style(Style {
                    position_type: PositionType::Absolute,
                    right: Val::Px(5.0),
                    bottom: Val::Px(5.0),
                    ..default()
                });
                shop_item.spawn(text1);
                shop_item.spawn(text2);
            });
            #[cfg(feature = "inspect")]
            button.insert(Name::new(format!("Buy {}", item.name())));
        }
        // TODO: Make this a sprite
        window.spawn((
            ButtonBundle {
                style: Style {
                    position_type: PositionType::Absolute,
                    right: Val::Px(30.0),
                    top: Val::Px(30.0),
                    width: Val::Px(128.0),
                    height: Val::Px(128.0),
                    ..default()
                },
                background_color: Color::RED.into(),
                ..default()
            },
            ShopButtonAction::Quit,
        ));
    });
    #[cfg(feature = "inspect")]
    window.insert(Name::new("Shop Window"));
}

fn close_shop(mut commands: Commands, window: Query<Entity, With<ShopWindow>>) {
    let window = window.single();
    commands.entity(window).despawn_recursive();
}

fn shop_action(
    mut commands: Commands,
    interactions: Query<
        (Entity, &Interaction, &ShopButtonAction),
        (Changed<Interaction>, With<Button>),
    >,
    mut menu_state: ResMut<NextState<ShopState>>,
    mut owned_items: Query<&mut OwnedItems, With<Player>>,
    mut money: Query<&mut Coins, With<Player>>,
    mut cooldown: Query<&mut Cooldown, With<Player>>,
    mut damage: Query<&mut Damage, With<Player>>,
    mut health: Query<&mut Health, With<Player>>,
    mut regen: Query<&mut RegenCooldown, With<Player>>,
) {
    // TODO: Prevent buying the same item repeatedly
    for (button_entity, interaction, action) in &interactions {
        if *interaction == Interaction::Pressed {
            match action {
                ShopButtonAction::Buy(item) => {
                    if let Some(new_money) = money.single().0.checked_sub(item.price()) {
                        if !owned_items.single_mut().0.insert(*item) {
                            println!("already own {item}");
                            continue;
                        }
                        money.single_mut().0 = new_money;
                        match item {
                            ShopItem::DualWield => {
                                cooldown.single_mut().0 = PLAYER_ATTACK_COOLDOWN.0 / 2.0
                            }
                            ShopItem::TameDragon => {}
                            ShopItem::HealthIncrease => {
                                health.single_mut().max = PLAYER_HEALTH_INITIAL * 2.0
                            }
                            ShopItem::DamageIncrease => {
                                damage.single_mut().0 = PLAYER_DAMAGE_INITIAL.0 * 2.0
                            }
                            ShopItem::RegenIncrease => regen.single_mut().0.set_duration(
                                Duration::from_secs_f32(PLAYER_REGEN_TIMER_INITIAL / 2.0),
                            ),
                        }
                        commands.entity(button_entity).insert(BackgroundColor(
                            Color::hex(INACTIVE_SHOP_BUTTON_COLOR).unwrap(),
                        ));
                    } else {
                        println!("can't afford");
                    }
                }
                ShopButtonAction::Quit => menu_state.set(ShopState::JustClosed),
            }
        }
    }
}

fn shopkeep_collision(
    player: Query<&Transform, With<Player>>,
    shop_keep: Query<&Transform, With<ShopKeep>>,
    current_state: Res<State<ShopState>>,
    mut next_state: ResMut<NextState<ShopState>>,
) {
    let current_state = *current_state.get();
    if current_state == ShopState::Open {
        return;
    }
    let player = player.single();
    let shop_keep = shop_keep.single();
    let colliding = collide(
        player.translation,
        PLAYER_SIZE,
        shop_keep.translation,
        SHOPKEEP_SIZE,
    )
    .is_some();
    if current_state == ShopState::Closed && colliding {
        next_state.set(ShopState::Open);
    } else if current_state == ShopState::JustClosed && !colliding {
        next_state.set(ShopState::Closed)
    }
}

fn give_kill_rewards(
    mut deaths: EventReader<Death>,
    mut money: Query<&mut Coins, With<Player>>,
    rewards: Query<&KillReward>,
) {
    // Could be problematic if between the death being fired the entity has been despawned?
    for death in deaths.read() {
        let mut player_money = money.single_mut();
        // TODO: do we need source if player is the only thing killing
        if death.source.is_some() {
            match rewards.get(death.target) {
                Ok(reward) => {
                    player_money.0 = player_money.0.saturating_add(reward.0);
                }
                // make sure we don't despawn entity before processing kill rewards
                #[cfg(debug_assertions)]
                Err(bevy::ecs::query::QueryEntityError::NoSuchEntity(_)) => unreachable!(),
                Err(_) => (),
            }
        }
    }
}

fn update_money_text(
    money: Query<&Coins, (With<Player>, Changed<Coins>)>,
    mut text: Query<&mut Text, With<MoneyText>>,
) {
    let Ok(new_money) = money.get_single() else {
        return;
    };
    let mut text = text.single_mut();
    text.sections[0].value = format!("{}", new_money.0);
}
