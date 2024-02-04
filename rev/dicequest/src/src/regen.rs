use crate::{GameState, Health, PLAYER_HEALTH_INITIAL, PLAYER_REGEN_AMOUNT};
use bevy::prelude::*;

pub struct RegenPlugin;

#[derive(Component)]
pub struct RegenCooldown(pub Timer);

impl Plugin for RegenPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(Update, process_regen.run_if(in_state(GameState::Running)));
    }
}

fn process_regen(mut player: Query<(&mut Health, &mut RegenCooldown)>, time: Res<Time>) {
    let (mut health, mut cooldown) = player.single_mut();
    cooldown.0.tick(time.delta());
    if health.current < health.max && cooldown.0.finished() {
        health.current = PLAYER_HEALTH_INITIAL.min(health.current + PLAYER_REGEN_AMOUNT);
    }
}
